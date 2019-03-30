# Wordpress plugin for MobileApp API's

Please find the API end points below : </br>

### 1) Authentication  </br>
   As an intial step you need to install JWT Auth Plugin in your wordpress setup.</br>
   Please find the plugin link below : </br>
    https://wordpress.org/plugins/jwt-authentication-for-wp-rest-api/</br>
 
### 2) Registration </br> 
 ```
  ENDPOINT : YOUR_SITE_URL/wp-json/mobileapi/v1/register 
  ```
### 3) Forgot Password </br>
 ```
   ENDPOINT : YOUR_SITE_URLL/wp-json/mobileapi/v1/retrieve_password
   ```
   
### 4) Get User Profile image with wp user Avatar plugin </br>
 https://wordpress.org/plugins/wp-user-avatar/ 

 ```
  ENDPOINT : YOUR_SITE_URL/wp-json/mobileapi/v1/GetUserImage
  ```
  
### 5) Login with Facebook</br>
 ```
  ENDPOINT : YOUR_SITE_URL/wp-json/mobileapi/v1/facebook_login
  ```
  
### 6) Fetch user UserId using JWT:Auth token</br> 
 
 ```
 ENDPOINT : NO ENDPOINT IT IS FUNCTION
 ```
 
### 7) Validate JWT:Auth Token</br>
 ```
 ENDPOINT : WP_URL/wp-json/mobileapi/v1/validate_token
 ```
 
