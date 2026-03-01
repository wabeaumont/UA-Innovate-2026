# Secure Healthcare
## Initial Setup
### 1. Navigate into directory where repository was stored on your machine in Command Prompt
### 2. Install all dependencies with "pip install -r requirements.txt"
### 2.1. Ignore any errors related to "Getting requirements to build wheel"
### 3. Run webapp with "python app.py" and it will generate a secret key value for you if one has not already been set. Copy that value and stop the program with Control + C.
### 4. Set encryption key with "setx ENCRYPTION_KEY (key value)".
### 4. Delete .db file in instance folder and  run webapp again with "python app.py"
### 5. Initialize database by navigating to "http://127.0.0.1:5000/init-db"
### 5.1. Copy test account information for testing purposes and for default logins
### 5.2. Go to login page by clicking "Go to login page"
## Registering
### 1. Click "Register here"
### 2. Enter all information as prompted and then click "Create Account"
### 3. Use the QR code or the Secret key provided to activate your account through the 2FA service of your choice and then enter the Verification Code and click "Verify and Activate 2FA"
### 4. Log in following the "Logging In" process described below
### 5. Click "Create your profile"
### 6. Enter all information as prompted and then click "Create Profile"
## Logging In
### 1. Enter Username and Password and click "Login"
### 2. Enter Verification Code from 2FA service and click "Verify Code"
## Admin Dashboard
### 1. Users are available under "User Management"
### 2. Security informaiton is available under "System Security"
### 3. To add a new user, click "Add New User"
### 4. Enter all information as prompted and then click "Create User"
### 4.1. Copy the temporary password and secret key and send it to your user in a secure manner.
## Doctor Dashboard
### 1. Patients are available under "Patient Directory"
### 2. To add a new patient, click "Add New Patient" 
### 2.1. Enter all information as prompted and then click "Create Patient"
### 2.2. Copy the temporary password and send it to your patient in a secure manner.
### 2.3. Review patient information and click "Back to Dashboard"
### 3. To view a patient's information, click "View" under that patient's "Actions" tab
### 4. To add a medical record for a patient, click "Add Record"
### 4.1. Enter all information as prompted and then click "Save Medical Record"
### 4.2. Review patient information and click "Back to Dashboard"
## Patient Dashboard
### 1. Personal information is available under "Personal Information"
### 2. Medical records are available under "Your Medical Records"
### 3. Click each medical record to view the details of each record
## Logging Out
### 1. Click "Logout"