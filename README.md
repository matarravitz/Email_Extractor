<p align="center">
  <img src="Images/Email_Extractor.png" width="400"/>
</p>

<p align="center">
  <b>Email Extractor</b> is a web-based tool that extracts email addresses from a given URL.
</p> 

## 📋 Usage 

1. Go to the deployed website.
2. Log in securely via AWS Cognito.
3. Enter any URL you want to scan.
4. The tool will extract all visible email addresses from the page and display them.
5. Previous results are cached using DynamoDB to improve performance on repeated scans.

## 💼 What I Built  
This project demonstrates a complete serverless application on AWS. Key components include:

- 🔐 **Authentication**: Implemented secure user login with AWS Cognito.
- 🌐 **Hosting**: Deployed a static site on S3 with public access configuration.
- ⚙️ **Backend Logic**: Built a Python Lambda function triggered by API Gateway to parse the HTML content from a given URL and extract email addresses.
- 🧠 **Caching**: Integrated DynamoDB to store and reuse results for repeated queries.
- 🧪 **Error Handling**: Handled edge cases like invalid URLs, pages without emails, and duplicate results.  

## 🔄 Workflow  

This project uses a GitHub Actions workflow to deploy updates automatically.

- When code is pushed to the `main` branch, the updated Lambda function is automatically packaged and deployed to AWS using the AWS CLI.
  
## 🌱 Reflection

🌼 This project was my first attempt at building a full cloud-based application, and a valuable learning experience.
It helped me understand the basics of serverless architecture and how different AWS services work together.
I'm looking forward to learning more and exploring new technologies.

