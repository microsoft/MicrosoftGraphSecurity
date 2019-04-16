This project has adopted the [Microsoft Open Source Code of Conduct](http://microsoft.github.io/codeofconduct). For more information see the [Code of Conduct FAQ](http://microsoft.github.io/codeofconduct/faq.md) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

# Microsoft Graph Security PowerShell Module [ Unofficial]
Welcome to the Unofficial Microsoft Graph Security PowerShell module!

This module is a collection of easy-to-use cmdlets and functions designed to make it easy to interface with the Microsoft Graph Security API.

Why is it unofficial, you ask? Even though this module was designed by Microsoft employees, it is NOT a formal part of the Graph Security API product and you will not be able to get support through standard Microsoft channels. That said, if you have problems or questions, please open an issue here on this Github repo. The authors will be more than happy to help. 


## Prerequisites

To get value from this module you must...


...have PowerShell v5+ (comes standard on Windows 10)

...have configured authorization for access by registering an application.  See [Authorization and the Microsoft Graph Security API](https://docs.microsoft.com/en-us/graph/security-authorization#register-an-application-in-the-azure-ad-v20-endpoint)

### App Registration Settings

Register an application with Azure AD with the following
-  **Authentication** 
     - Select the Suggested Redirect URI to be `urn:ietf:wg:oauth:2.0:oob` 
     - Select Implicit grant issued by the authorization endpoint `Access Tokens`
-  **API Permissions** 
      - Add Microsoft Graph Delegated Permissions `SecurityEvents.Read.Al`l and/or `SecurityEvents.ReadWrite.All`


## Getting Started

To get started with the module, open your PowerShell terminal as an administrator and install the module from the PSGallery by running this simple command:
```
Install-Module MicrosoftGraphSecurity
```
If this is your first time installing a module, you will get prompted to install the Nuget Package Provider. Nuget is the Package/Module manager used by the PSGallery repository.

## Contributing

Apologies, we are not currently opening up this project for contribution outside of our existing team. This may change in the future if there is enough interest.

## Authors


* **Anisha Gupta** - *Co-Lead Dev* - [LinkedIn](https://www.linkedin.com/in/ani6gup/)
* **Nicholas DiCola** - *Co-Lead Dev* - [LinkedIn](https://linkedin.com/in/ndicola/)
* **Mike Kassis** - *Test Design* - [LinkedIn](www.linkedin.com/in/mrkassis)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

## License

This project has adopted the [Microsoft Open Source Code of Conduct](http://microsoft.github.io/codeofconduct). For more information see the [Code of Conduct FAQ](http://microsoft.github.io/codeofconduct/faq.md) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments. 
