import hashlib
import time

def verify_client(username, password, nonce):
    try:
        with open("credentials.txt", "r") as f:
            lines = f.readlines()

        updated_lines = []
        user_found = False
        response = None

        for line in lines:
            stored_username, stored_password, attempt, until_block, sessionkey = line.strip().split(":")
            attempt = int(attempt)
            until_block = float(until_block)
            stored_password_with_hash = hashlib.sha3_512((stored_password+nonce).encode()).hexdigest()
            print("stored password sha with hash :", stored_password_with_hash)

            if stored_username == username:
                user_found = True
                current_time = time.time()

                # Case 4: User is blocked
                if current_time < until_block:
                    print(f"You are blocked. Try after {int(until_block - current_time)} seconds.")
                    response = "blocked"

                # Case 5: Correct password
                elif stored_password_with_hash == password:
                    print("Login successful")
                    attempt = 0
                    response = stored_username

                # Case 2 & 3: Wrong password
                else:
                    attempt += 1
                    print(f"Attempt {attempt} failed for {username}")
                    response = "passwordfailed"

                    if attempt >= 3:
                        until_block = current_time + 24 * 60 * 60
                        print(f"Too many attempts. {username} is blocked for 24 hours.")
                        response = "blocked"

                updated_lines.append(f"{stored_username}:{stored_password}:{attempt}:{until_block}:{sessionkey}\n")
            else:
                updated_lines.append(line)

        # Case 1: Username not found
        if not user_found:
            return "user_notfound"

        # Save updated file
        with open("credentials.txt", "w") as f:
            f.writelines(updated_lines)

        return response

    except FileNotFoundError:
        print("credentials.txt file not found")
        return None