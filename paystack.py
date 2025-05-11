import requests

def verify_paystack_transaction(reference):
    url = f"https://api.paystack.co/transaction/verify/{reference}"
    
    headers = {
        "Authorization": "Bearer YOUR_PAYSTACK_SECRET_KEY",  # Replace with your secret key
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Test the function with a sample reference ID
reference = "sample_payment_reference"  # Replace with an actual reference from Paystack
result = verify_paystack_transaction(reference)
print(result)