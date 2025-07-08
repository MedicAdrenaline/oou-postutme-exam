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

def send_email(to_email, subject, content):
    send_bulk_email([to_email], subject, content)

def send_otp_email(to_email, otp):
    content = f"Hi,\n\nYour OTP is: {otp}\n\nBest regards,\nMedic Adrenaline, \nClick on the Report not spam so as to receive our emails(PINs and...) notifications as fast as possible in your inbox"
    send_email(to_email, "Verify your Exam Practice Account", content)

def send_reset_password_email(to_email, token):
    content = (
        f"Hi,\n\n"
        f"Your password reset token is: {token}\n\n"
        f"This token will expire in 1 hour.\n\n"
        f"Best regards,\nMedic Adrenaline"
    )
    send_email(to_email, "Password Reset Request", content)

def send_exam_pins_email(to_email, pins_dict):
    content = "Hi,\n\nHere are your PINs:\n\n"
    for mode, pin in pins_dict.items():
        content += f"- {mode}: {pin}\n"
    
    content += (
        "\nNote: Do not disclose your PIN. Once it is activated on your device only. "
        "This PIN is tied to that specific device and cannot be accessed on another device. "
        "Please contact the admin via the login page if you need to access your account on a new device.\n\n"
        "Best regards,\nMedic Adrenaline Team"
    )
    
    send_email(to_email, "Your Exam Practice PIN(s)", content)

def send_exam_pins_email_bulk(recipient_emails, pins_dict):
    content = "Dear Student,\n\nHere are your PIN(s) for the selected exam mode(s):\n\n"
    
    for mode, pin in pins_dict.items():
        content += f"{mode.upper()} PIN: {pin}\n"
    
    content += (
        "\nNote: Do not disclose your PIN. Once it is activated on your device only. "
        "This PIN is tied to that specific device and cannot be accessed on another device. "
        "Please contact the admin via the login page if you need to access your account on a new device.\n\n"
        "Best regards,\nMedic Adrenaline Team"
    )
    
    send_bulk_email(recipient_emails, "Your Exam PIN(s)", content)