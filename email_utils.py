import yagmail
import os
from config import Config

email_accounts = Config.EMAIL_ACCOUNTS
email_index_file = 'email_index.txt'

# Initialize index file if it doesn't exist
if not os.path.exists(email_index_file):
    with open(email_index_file, 'w') as f:
        f.write('0')

def get_email_index():
    try:
        with open(email_index_file, 'r') as f:
            return int(f.read().strip())
    except:
        return 0

def update_email_index(index):
    with open(email_index_file, 'w') as f:
        f.write(str(index))

def send_bulk_email(to_emails, subject, content):
    index = get_email_index()
    creds = email_accounts[index]
    email_user = creds["EMAIL_HOST_USER"]
    email_password = creds["EMAIL_HOST_PASSWORD"]

    try:
        yag = yagmail.SMTP(user=email_user, password=email_password)
        for to_email in to_emails:
            try:
                yag.send(to=to_email, subject=subject, contents=content)
                print(f"[SUCCESS] Email sent to {to_email} from {email_user}")
            except Exception as e:
                print(f"[FAIL] Could not send to {to_email}: {e}")
        update_email_index((index + 1) % len(email_accounts))
    except Exception as e:
        print(f"[ERROR] Email account {email_user} failed to connect: {e}")

# ===== SINGLE EMAIL SENDERS =====
import yagmail
import os
from config import Config

email_accounts = Config.EMAIL_ACCOUNTS
email_index_file = 'email_index.txt'

# Initialize index file if it doesn't exist
if not os.path.exists(email_index_file):
    with open(email_index_file, 'w') as f:
        f.write('0')

def get_email_index():
    try:
        with open(email_index_file, 'r') as f:
            return int(f.read().strip())
    except:
        return 0

def update_email_index(index):
    with open(email_index_file, 'w') as f:
        f.write(str(index))

def send_bulk_email(to_emails, subject, content):
    index = get_email_index()
    creds = email_accounts[index]
    email_user = creds["EMAIL_HOST_USER"]
    email_password = creds["EMAIL_HOST_PASSWORD"]

    try:
        yag = yagmail.SMTP(user=email_user, password=email_password)
        for to_email in to_emails:
            try:
                yag.send(to=to_email, subject=subject, contents=content)
                print(f"[SUCCESS] Email sent to {to_email} from {email_user}")
            except Exception as e:
                print(f"[FAIL] Could not send to {to_email}: {e}")
        update_email_index((index + 1) % len(email_accounts))
    except Exception as e:
        print(f"[ERROR] Email account {email_user} failed to connect: {e}")

# ===== SINGLE EMAIL SENDERS =====
def send_reset_password_email(to_email, token):
    subject = "Password Reset Request"
    content = (
        f"Hi,\n\n"
        f"Your password reset token is: {token}\n\n"
        f"This token will expire in 1 hour.\n\n"
        f"Best regards,\nMedic Adrenaline")
    send_email(to_email, subject, content)

def send_email(to_email, subject, content):
    send_bulk_email([to_email], subject, content)

def send_otp_email(to_email, otp):
    content = f"Hi,\n\nYour OTP is: {otp}\n\nBest regards,\nMedic Adrenaline"
    send_email("Verify your Exam Practice Account", content, to_email)

def send_exam_pins_email(to_email, pins_dict):
    content = "Hi,\n\nHere are your PINs:\n\n"
    for mode, pin in pins_dict.items():
        content += f"- {mode}: {pin}\n"
    
    # Adding the device-specific note
    content += (
        "\nNote: Do not disclose your PIN. Once it is activated on your device only. "
        "This PIN is tied to that specific device and cannot be accessed on another device. "
        "Please contact the admin via the login page if you need to access your account on a new device.\n\n"
        "Please keep your PIN safe and use it only once.\n\n"
        "Best regards,\nMedic Adrenaline Team"
    )
    
    send_email("Your Exam Practice PIN(s)", content, to_email)

# ===== BULK EMAIL SENDERS =====

def send_otp_email_bulk(to_emails, otp):
    content = f"Hi,\n\nYour OTP is: {otp}\n\nBest regards,\nMedic Adrenaline"
    send_bulk_email(to_emails, "Verify your Exam Practice Account", content)

def send_exam_pins_email_bulk(recipient_emails, pins_dict):
    subject = "Your Exam PIN(s)"
    content = "Dear Student,\n\nHere are your PIN(s) for the selected exam mode(s):\n\n"
    
    for mode, pin in pins_dict.items():
        content += f"{mode.upper()} PIN: {pin}\n"
    
    content += (
        "\nNote: Do not disclose your PIN. Once it is activated on your device only. "
        "This PIN is tied to that specific device and cannot be accessed on another device. "
        "Please contact the admin via the login page if you need to access your account on a new device.\n\n"
        "Please keep your PIN safe and use it only once.\n\n"
        "Best regards,\nMedic Adrenaline Team"
    )
    
    send_bulk_email(recipient_emails, subject, content)
def send_email(to_email, subject, content):
    send_bulk_email([to_email], subject, content)

def send_otp_email(to_email, otp):
    content = f"Hi,\n\nYour OTP is: {otp}\n\nBest regards,\nMedic Adrenaline"
    send_email("Verify your Exam Practice Account", content, to_email)

def send_exam_pins_email(to_email, pins_dict):
    content = "Hi,\n\nHere are your PINs:\n\n"
    for mode, pin in pins_dict.items():
        content += f"- {mode}: {pin}\n"
    
    # Adding the device-specific note
    content += (
        "\nNote: Do not disclose your PIN. Once it is activated on your device only. "
        "This PIN is tied to that specific device and cannot be accessed on another device. "
        "Please contact the admin via the login page if you need to access your account on a new device.\n\n"
        "Please keep your PIN safe and use it only once.\n\n"
        "Best regards,\nMedic Adrenaline Team"
    )
    
    send_email("Your Exam Practice PIN(s)", content, to_email)

# ===== BULK EMAIL SENDERS =====

def send_otp_email_bulk(to_emails, otp):
    content = f"Hi,\n\nYour OTP is: {otp}\n\nBest regards,\nMedic Adrenaline"
    send_bulk_email(to_emails, "Verify your Exam Practice Account", content)

def send_exam_pins_email_bulk(recipient_emails, pins_dict):
    subject = "Your Exam PIN(s)"
    content = "Dear Student,\n\nHere are your PIN(s) for the selected exam mode(s):\n\n"
    
    for mode, pin in pins_dict.items():
        content += f"{mode.upper()} PIN: {pin}\n"
    
    content += (
        "\nNote: Do not disclose your PIN. Once it is activated on your device only. "
        "This PIN is tied to that specific device and cannot be accessed on another device. "
        "Please contact the admin via the login page if you need to access your account on a new device.\n\n"
        "Please keep your PIN safe and use it only once.\n\n"
        "Best regards,\nMedic Adrenaline Team"
    )
    
    send_bulk_email(recipient_emails, subject, content)