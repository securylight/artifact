{
    "model": "gpt-5.4",
    "max_chars_per_source": 18000,
    "vulnerabilities": [
        {
            "id": "ssrf",
            "name": "Server-Side Request Forgery",
            "link_groups": {
                "definition": [
                    "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
                ],
                "attack": [
                    "https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery.md"
                ],
                "prevention": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
                ]
            }
        },
        {
            "id": "file_upload",
            "name": "Unrestricted File Upload",
            "link_groups": {
                "definition": [
                    "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
                ],
                "attack": [
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files"
                ],
                "prevention": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
                ]
            }
        }
    ]
}
