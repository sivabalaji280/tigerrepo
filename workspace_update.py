import subprocess
import sys
import json
import base64
import re
import time

# Install required package
subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'requests'])

import requests

notebook_not_updated = True


def exit_program(message):
    """
    Exit the program with a message and status code 0.

    Args:
        message (str): The message to display before exiting.
    """
    print(message)
    print("-" * 30)
    sys.exit(0)


def get_token(client_id, client_secret, tenant_id, username, password):
    """
    Acquire an access token using Azure AD credentials.

    Args:
        client_id (str): The client ID of the Azure AD application.
        client_secret (str): The client secret of the Azure AD application.
        tenant_id (str): The ID of the Azure AD tenant.
        username (str): The username for authentication.
        password (str): The password for authentication.

    Returns:
        str: The access token.
    """
    try:
        # Define the token URL and scopes
        token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
        scopes = 'https://api.fabric.microsoft.com/.default'

        # Create a payload for token request
        payload = {
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scopes,
            "username": username,
            "password": password,
            "grant_type": 'password'
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        # Acquire a token using client credentials and scopes
        result = requests.request("POST", token_url, headers=headers, data=payload)

        if result.status_code == 200:
            access_token = result.json()["access_token"]
            return access_token
        else:
            exit_program("Error Acquiring Token. Error: " + str(result.text))
    except Exception as err:
        raise err


def process_notebook_definition(api_response, workspace_id, def_lakehouse_id, def_lakehouse_name):
    """
    Extracts values from YAML data and updates the notebook definition payload.

    Args:
        api_response (requests.Response): API response containing the notebook definition payload.
        workspace_id (str): The ID of the workspace.
        def_lakehouse_id (str): The ID of the default lakehouse.
        def_lakehouse_name (str): The name of the default lakehouse.

    Returns:
        tuple: A tuple containing a flag indicating if the update was performed and the updated payload.
    """
    try:
        payload_encoded = api_response.json()['definition']['parts'][0]['payload']
        decoded_payload = base64.b64decode(payload_encoded)
        decoded_payload_str = decoded_payload.decode('utf-8')
        # print(decoded_payload_str)

        default_lakehouse_value = def_lakehouse_id
        default_lakehouse_name_value = def_lakehouse_name
        default_lakehouse_workspace_id_value = workspace_id
        # id_value = yaml_data.get("testLakehouse", {}).get("defaultLakehouse")

        if re.search(r'#\s*META\s*["\']lakehouse["\']', decoded_payload_str):
            updated_content = re.sub(r'"default_lakehouse": "[^"]+"',
                                     f'"default_lakehouse": "{default_lakehouse_value}"', decoded_payload_str)
            updated_content = re.sub(r'"default_lakehouse_name": "[^"]+"',
                                     f'"default_lakehouse_name": "{default_lakehouse_name_value}"', updated_content)
            updated_content = re.sub(r'"default_lakehouse_workspace_id": "[^"]+"',
                                     f'"default_lakehouse_workspace_id": "{default_lakehouse_workspace_id_value}"',
                                     updated_content)
            # updated_content = re.sub(r'"id": "[^"]+"', f'"id": "{id_value}"', updated_content)

            encoded_payload_str = updated_content.encode('utf-8')
            new_payload_str = base64.b64encode(encoded_payload_str).decode()
            update_flag = True
        else:
            print("No Lakehouse Dependencies to update. Skipping the Update Process...")
            update_flag = False
            new_payload_str = payload_encoded

        return update_flag, new_payload_str
    except Exception as err:
        raise err


def update_notebook_definition(token, notebook_id, new_payload_str, notebook_name, workspace_id):
    """
    Updates the notebook definition using the new payload.

    Args:
        token (str): Authentication token.
        notebook_id (str): Notebook ID.
        new_payload_str (str): Updated notebook payload.
        notebook_name (str): Notebook name.
        workspace_id (str): The ID of the workspace.
    """
    global notebook_not_updated
    try:
        header = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
        notebook_update_url = f"https://api.fabric.microsoft.com/v1/workspaces/{workspace_id}/notebooks/" \
                              f"{notebook_id}/updateDefinition"
        update_payload = {
            "definition": {
                "parts": [
                    {
                        "path": "notebook-content.py",
                        "payload": new_payload_str,
                        "payloadType": "InlineBase64"
                    }
                ]
            }
        }
        update_response = requests.post(url=notebook_update_url, headers=header, json=update_payload)

        if update_response.status_code == 200:
            print("Updated the Notebook Definition Successfully for - ", notebook_name)
            notebook_not_updated = False
        elif update_response.status_code == 202:
            print('Update Definition Call is queued. Response: ', update_response.headers)
            location = update_response.headers["Location"]
            retry_after = update_response.headers["Retry-After"]
            print(f'Wait Time is - {retry_after}s')
            time.sleep(int(retry_after))

            while True:
                queue_response = requests.get(url=location, headers=header)
                header_data = queue_response.json()

                if header_data['error'] is not None:
                    exit_program("Error while getting the notebook definition. Error: " + str(queue_response.text))

                if header_data['percentComplete'] == 100:
                    print("Updated the Notebook Definition Successfully for - ", notebook_name)
                    notebook_not_updated = False
                    break

                time.sleep(20)

        else:
            exit_program("Error while updating the notebook definition. Error: " + str(update_response.text))
    except Exception as err:
        raise err


def get_notebook_items_and_update(token, workspace_id, def_lakehouse_id, def_lakehouse_name):
    """
    Retrieves notebook items and updates their definitions.

    Args:
        token (str): Authentication token.
        workspace_id (str): The ID of the workspace.
        def_lakehouse_id (str): The ID of the default lakehouse
        def_lakehouse_name (str): The name of the default lakehouse
    """
    try:
        header = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
        notebook_url = f"https://api.fabric.microsoft.com/v1/workspaces/{workspace_id}/notebooks"
        notebook_response = requests.get(url=notebook_url, headers=header)

        if notebook_response.status_code == 200:
            notebook_list = notebook_response.json()['value']
            for notebook in notebook_list:
                notebook_id = notebook['id']
                notebook_name = notebook['displayName']
                print("-"*30)
                print('Updating Notebook Def for:', notebook_name)
                print('Notebook Item info:', notebook)

                definition_url = f"https://api.fabric.microsoft.com/v1/workspaces/{workspace_id}/" \
                                 f"notebooks/{notebook_id}/getDefinition"
                def_response = requests.post(url=definition_url, headers=header)

                if def_response.status_code == 202:
                    print('Get Definition Call is queued. Response:', def_response.headers)
                    location = def_response.headers["Location"]
                    retry_after = def_response.headers["Retry-After"]
                    print(f'Wait Time is - {retry_after}s')
                    time.sleep(int(retry_after))

                    while True:
                        queue_response = requests.get(url=location, headers=header)
                        header_data = queue_response.json()

                        if header_data['error'] is not None:
                            exit_program("Error while getting the notebook definition. Error: " +
                                         str(queue_response.text))

                        if header_data['percentComplete'] == 100:
                            def_response_new = requests.get(url=location+'/result', headers=header)
                            update_flag, new_payload_str = process_notebook_definition(def_response_new, workspace_id, def_lakehouse_id, def_lakehouse_name)
                            if update_flag:
                                update_notebook_definition(token, notebook_id, new_payload_str, notebook_name,
                                                           workspace_id)
                            break

                        time.sleep(20)

                elif def_response.status_code == 200:
                    update_flag, new_payload_str = process_notebook_definition(def_response, workspace_id, def_lakehouse_id, def_lakehouse_name)

                    if update_flag:
                        update_notebook_definition(token, notebook_id, new_payload_str, notebook_name, workspace_id)
                else:
                    exit_program("Error while getting the notebook definition. Error: " + str(def_response.text))
        else:
            exit_program("Error while getting the notebook list. Error: " + str(notebook_response.text))
    except Exception as err:
        raise err


def get_git_status(workspace_id, access_token):
    """
    Retrieve the Git status of a workspace using the Fabric API.

    Args:
        workspace_id (str): The ID of the workspace.
        access_token (str): The access token for authentication.

    Returns:
        tuple: A tuple containing the workspace head, commit hash, and the status response JSON.
    """
    try:
        git_header = {'Content-Type': 'application/json', 'Authorization': f'Bearer {access_token}'}
        git_status_url = f"https://api.fabric.microsoft.com/v1/workspaces/{workspace_id}/git/status"
        status_response = requests.get(url=git_status_url, headers=git_header)

        if status_response.status_code == 200:
            workspace_head_var = status_response.json()["workspaceHead"]
            commit_hash_var = status_response.json()["remoteCommitHash"]
            return workspace_head_var, commit_hash_var, status_response.json()
        else:
            exit_program("Error Getting Git Status. Error: " + str(status_response.text))
    except Exception as err:
        raise err


def git_commit(workspace_id, workspace_head_var, access_token):
    """
    Commit the changes to git with the changes made in the workspace to the connected remote branch.

    Args:
        workspace_id (str): The ID of the workspace.
        workspace_head_var (str): Full SHA hash that the workspace is synced to.
        access_token (str): The access token for authentication.
    Returns:
        BOOL: the commit flag
    """
    git_header = {'Content-Type': 'application/json', 'Authorization': f'Bearer {access_token}'}
    commit_url = f"https://api.fabric.microsoft.com/v1/workspaces/{workspace_id}/git/commitToGit"

    commit_req_body = {
        "mode": "All",
        "workspaceHead": workspace_head_var,
        "comment": "Item commit through git api ***NO_CI***"
    }

    print("Commits available, committing the changes...")
    update_response = requests.post(url=commit_url, headers=git_header, json=commit_req_body)
    if update_response.status_code == 200:
        exit_program("Committed the changes")
    elif update_response.status_code == 202:
        print('Commit Call is queued. Response:', update_response.headers)
        location = update_response.headers["Location"]
        retry_after = update_response.headers["Retry-After"]
        print(f'Wait Time is - {retry_after}s')
        time.sleep(int(retry_after))

        while True:
            queue_response = requests.get(url=location, headers=git_header)
            header_data = queue_response.json()

            if header_data['error'] is not None:
                exit_program("Error while committing the changes to git. Error: " +
                             str(queue_response.text))

            if header_data['percentComplete'] == 100:
                break

            time.sleep(20)
        print('Git Commit is Complete.')
    else:
        exit_program(f"Error while committing the changes. \nError: {update_response.text} .\nExiting the process!!")


def update_workspace(workspace_id, workspace_head_var, commit_hash_var, access_token):
    """
    Update the workspace using the Fabric API.

    Args:
        workspace_id (str): The ID of the workspace.
        workspace_head_var (str): Full SHA hash that the workspace is synced to.
        commit_hash_var (str): The commit hash.
        access_token (str): The access token for authentication.
    """
    try:
        git_header = {'Content-Type': 'application/json', 'Authorization': f'Bearer {access_token}'}
        update_url = f"https://api.fabric.microsoft.com/v1/workspaces/{workspace_id}/git/updateFromGit"

        git_update_req_body = {
          "workspaceHead": workspace_head_var,
          "remoteCommitHash": commit_hash_var,
          "conflictResolution": {
            "conflictResolutionType": "Workspace",
            "conflictResolutionPolicy": "PreferRemote"
          },
          "options": {
            "allowOverrideItems": True
          }
        }

        update_response = requests.post(url=update_url, headers=git_header, json=git_update_req_body)

        if update_response.status_code == 202:
            print('Workspace update call is queued. Response:', update_response.headers)
            location = update_response.headers["Location"]
            retry_after = update_response.headers["Retry-After"]
            print(f'Wait Time is - {retry_after}s')
            time.sleep(int(retry_after))

            while True:
                queue_response = requests.get(url=location, headers=git_header)
                header_data = queue_response.json()

                if header_data['error'] is not None:
                    exit_program("Error while updating the workspace. \nError: " + str(queue_response.text))

                if header_data['percentComplete'] == 100:
                    break

                time.sleep(20)
            print("Updated the Workspace!")
        elif update_response.status_code == 200:
            exit_program("Updated the Workspace!")
        else:
            exit_program("Error Updating the Workspace. Error: " + str(update_response.text))
    except Exception as err:
        raise err


def main():
    """
    Main function to execute the script.
    """
    # Define your Azure AD credentials
    client_id = sys.argv[1]
    client_secret = sys.argv[2]
    tenant_id = sys.argv[3]
    username = sys.argv[4]
    password = sys.argv[5]
    workspace_id = sys.argv[6]
    def_lakehouse_id = sys.argv[7]
    def_lakehouse_name = sys.argv[8]

    # Get Token String
    token_string = get_token(client_id, client_secret, tenant_id, username, password)

    # Get Git Commit
    workspace_head, commit_hash, status = get_git_status(workspace_id, token_string)

    print("-" * 30)
    print('Git Status: ', status)
    print("-" * 30)

    # Commit any new changes
    changes = []
    for change in status["changes"]:
        remote_change = change["remoteChange"]
        changes.append(remote_change)

    # Update Fabric Workspace
    if len(status["changes"]) > 0:
        print("Changes available to update.")
        print("Workspace update in progress!!!")
        update_workspace(workspace_id, workspace_head, commit_hash, token_string)
    else:
        print("-"*30)
        print("No Changes to Update the Workspace.")

    print("Proceeding toward updating the notebooks...")
# Update Notebook Definition with workspace lakehouse values
    get_notebook_items_and_update(token_string, workspace_id, def_lakehouse_id, def_lakehouse_name)

    # Get Git Commit
    workspace_head, commit_hash, status = get_git_status(workspace_id, token_string)

    print("-" * 30)
    print('Git Status: ', status)
    print("-" * 30)

    # Commit any new changes
    changes = []
    for change in status["changes"]:
        remote_change = change["remoteChange"]
        changes.append(remote_change)

    if None in changes:
        git_commit(workspace_id, workspace_head, token_string)
        # Get the new git commit
        workspace_head, commit_hash, status = get_git_status(workspace_id, token_string)
    else:
        print("-"*30)
        exit_program("No notebook changes to commit, exiting the process.")

if __name__ == "__main__":
    main()
