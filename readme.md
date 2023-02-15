# To Do Application

This application was created for evaluation for DubDub.ai's Internship procedure.

## API Routes

### User Routes
1. User Register `` POST ``

U͟R͟L͟: ``` user/register/ ```

L͟o͟g͟i͟n͟ r͟e͟q͟u͟i͟r͟e͟d͟: False

S͟a͟m͟p͟l͟e͟ I͟n͟p͟u͟t͟: 
```
{
  "email_address": "contact.sarveshjoshi@gmail.com", 
  "password": "yourpassword" 
}
```
S͟a͟m͟p͟l͟e͟ O͟u͟t͟p͟u͟t͟: 

Response with Status 201: for the successful creation of the user.
             
Response with status 406: for errors.

2. User Login `` POST ``

U͟R͟L͟: ``` user/login/ ```

L͟o͟g͟i͟n͟ r͟e͟q͟u͟i͟r͟e͟d͟: False

S͟a͟m͟p͟l͟e͟ I͟n͟p͟u͟t͟: 
```
{
  "email_address": "contact.sarveshjoshi@gmail.com", 
  "password": "yourpassword" 
}
```
S͟a͟m͟p͟l͟e͟ O͟u͟t͟p͟u͟t͟: 

Response with Status 200: for the successful login of the user.
             
Response with status 406: for errors.

### Task Routes

1. Create a Task `` POST ``
 
U͟R͟L͟: ``` task/create/ ```

L͟o͟g͟i͟n͟ r͟e͟q͟u͟i͟r͟e͟d͟: True

S͟a͟m͟p͟l͟e͟ I͟n͟p͟u͟t͟: 
```
{
  "task_title": "Any Task :)"
}
```
S͟a͟m͟p͟l͟e͟ O͟u͟t͟p͟u͟t͟: 

Response with Status 201: for the successful creation of the task.
             
Response with status 406: for errors.

2. Fetch a Task `` GET ``

U͟R͟L͟: ``` task/fetch/ ```

L͟o͟g͟i͟n͟ r͟e͟q͟u͟i͟r͟e͟d͟: True

S͟a͟m͟p͟l͟e͟ O͟u͟t͟p͟u͟t͟: 

Response with Status 200: with a list of tasks and details.
             
Response with status 406: for errors.

3. Tick a Task `` PATCH ``
 
U͟R͟L͟: ``` task/tick/<task_id>/ ``` 

L͟o͟g͟i͟n͟ r͟e͟q͟u͟i͟r͟e͟d͟: True

S͟a͟m͟p͟l͟e͟ O͟u͟t͟p͟u͟t͟: 

Response with Status 200: for the successful ticking of the task.
             
Response with status 406: for errors.

4. Delete a Task `` DELETE``
 
U͟R͟L͟: ``` task/delete/<task_id>/ ```

L͟o͟g͟i͟n͟ r͟e͟q͟u͟i͟r͟e͟d͟: True

S͟a͟m͟p͟l͟e͟ O͟u͟t͟p͟u͟t͟: 

Response with Status 200: for the successful deletion of the task.
             
Response with status 406: for errors.

5. Edit a Task `` PATCH ``
 
U͟R͟L͟: ``` task/edit/<task_id>/ ```
 
L͟o͟g͟i͟n͟ r͟e͟q͟u͟i͟r͟e͟d͟: True

S͟a͟m͟p͟l͟e͟ I͟n͟p͟u͟t͟: 
```
{
  "task_title": "Edited task :)"
}
```


S͟a͟m͟p͟l͟e͟ O͟u͟t͟p͟u͟t͟: 

Response with Status 200: for the successful editing of the task.
             
Response with status 406: for errors.

### Forgot Password Routes

1. Request to reset password `` POST ``
 
U͟R͟L͟: ``` user/reset_password/ ```

L͟o͟g͟i͟n͟ r͟e͟q͟u͟i͟r͟e͟d͟: False

S͟a͟m͟p͟l͟e͟ I͟n͟p͟u͟t͟: 
```
{
    "email_address": "contact.sarveshjoshi@gmail.com"
}
```
S͟a͟m͟p͟l͟e͟ O͟u͟t͟p͟u͟t͟: 

Response with Status 200: for successful sending of otp.
             
Response with status 406: for errors.

#### OTP will be sent to mentioned email address.

2. Set new password `` POST ``
 
U͟R͟L͟: ``` user/verify_otp/ ```

L͟o͟g͟i͟n͟ r͟e͟q͟u͟i͟r͟e͟d͟: False

S͟a͟m͟p͟l͟e͟ I͟n͟p͟u͟t͟: 
```
{
     "otp": "123456",
     "password": "NewPassword"
}
```
S͟a͟m͟p͟l͟e͟ O͟u͟t͟p͟u͟t͟: 

Response with Status 200: for successful reset of password.
             
Response with status 406: for errors.



## Contributing

The project was created completely by Sarvesh Joshi, for evaluation application for DubDub.ai
