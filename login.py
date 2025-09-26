import requests

# Login
login_url = "http://localhost:5000/api/login"
login_data = {
    "email": "adelerekehinde01@gmail.com",
    "password": "accelerate1625"  # Replace with your password
}
headers = {"Content-Type": "application/json"}

print(f"Sending login request to {login_url}")
response = requests.post(login_url, json=login_data, headers=headers)
print(f"Login response: {response.status_code} {response.text}")

if response.status_code == 200:
    token = response.json().get("access_token")
    print(f"Token: {token}")

    # Test /api/chat
    chat_url = "http://localhost:5000/api/chat"
    chat_data = {"message": "hello"}  # No Subject, no chat_id
    headers["Authorization"] = f"Bearer {token}"
    print(f"Sending chat request to {chat_url}")
    chat_response = requests.post(chat_url, json=chat_data, headers=headers)
    print(f"Chat response: {chat_response.status_code} {chat_response.text}")

    # Test /api/chats
    chats_url = "http://localhost:5000/api/chats"
    print(f"Sending chats request to {chats_url}")
    chats_response = requests.get(chats_url, headers=headers)  # No body for GET
    print(f"Chats response: {chats_response.status_code} {chats_response.text}")
else:
    print("Login failed")