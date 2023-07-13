## 1. Rust API - User Registration and Email Verification

In this article, we will explore the process of building a REST API in Rust with features like user registration, email verification, login, and logout capabilities. Our API will be powered by the high-performance Axum framework and will utilize the SQLx toolkit to store data in a SQLite database. It's worth noting that while we use SQLite in this tutorial, you can easily adapt the code to work with other databases supported by SQLx.

![Rust API - User Registration and Email Verification](https://codevoweb.com/wp-content/uploads/2023/07/Rust-API-User-Registration-and-Email-Verification.webp)

### Topics Covered

- Running the Rust API on Your Machine
- Running the Rust API with a Frontend Application
- Setting up the Rust Project
- Creating the HTML Email Templates
    - Creating the Base Layout
    - Creating the CSS Styles
    - Creating the Email Verification Template
- Handling Database Migrations
    - Starting with the Initial Migrations
    - Adding More Fields
- Creating the Database and Request Models
- Utility Functions for Sending the Emails
    - Getting Your SMTP Provider Credentials
    - Loading the Environment Variables
    - Creating a Struct with Methods for Sending the Emails
- Creating the API Response Models
- Creating the JWT Middleware Guard
- Creating the API Endpoint Handlers
    - Health Checker Handler
    - Register User with Email Verification Handler
    - Login User Handler
    - Verify Email Verification Token Handler
    - Logout User Handler
    - Retrieve Authentication User Credentials Handler
    - The Complete Code of the API Endpoint Handlers
- Creating the API Endpoints
- Registering the API Router
- Conclusion


Read the entire article here: [https://codevoweb.com/rust-api-user-registration-and-email-verification/](https://codevoweb.com/rust-api-user-registration-and-email-verification/)


## 2. Rust API - Forgot/Reset Password with Emails

In this guide, you will learn how to add a forgot/reset password feature to a Rust API. The API is built on top of the high-performance Axum framework and utilizes the SQLx crate for seamless integration with a database.

![Rust API - Forgot/Reset Password with Emails](https://codevoweb.com/wp-content/uploads/2023/07/Rust-API-Forgot-Reset-Password-with-Emails.webp)

### Topics Covered

- Running the Rust API Project Locally
- Running the Rust API with a Frontend App
- Setting up the Rust Project
- Generating the Password Reset HTML Email Template
- Sending the Emails via SMTP
- Performing Database Migrations
- Adding More Fields to the Database Model
- Creating the API Endpoint Handlers
    - Creating the Forgot Password Handler
    - Creating the Reset Password Handler
    - The Complete Code of the Route Handlers
- Registering the Forgot/Reset Password Routes
- Registering the Axum Router and Configuring the Server
- Conclusion
  
Read the entire article here: [https://codevoweb.com/rust-api-forgot-reset-password-with-emails/](https://codevoweb.com/rust-api-forgot-reset-password-with-emails/)
