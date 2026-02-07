Create an Azure architecture diagram.
Scenario:
One subscription, one VNet, three subnets, web tier, app tier, data tier, and monitoring.

Resources:

1. **Networking**
   - VNet: "vnet-contoso-auea-001" (10.10.0.0/16)
   - Subnets:
     - "snet-frontend" (10.10.1.0/24)
     - "snet-backend" (10.10.2.0/24)
     - "snet-data" (10.10.3.0/24)
   - Azure Firewall: "azfw-contoso"
   - NSGs for each subnet
   - Route table with default route to Firewall

2. **Web Tier**
   - Azure Front Door: "afd-contoso"
   - Application Gateway (WAF): "agw-contoso" in frontend subnet
   - App Service Plan: "asp-contoso-prod"
   - Web App: "app-frontend-portal"

3. **Application Tier**
   - Internal App Service Plan: "asp-contoso-backend"
   - Backend App Service: "app-order-api"
   - Azure Function App: "func-order-processor"
   - Azure Service Bus: "sb-contoso-orders"

4. **Data Tier**
   - SQL Server: "sqlsrv-contoso"
   - SQL Database: "sqldb-orders"
   - Storage Account: "stcontosodata001"
   - Azure Key Vault: "kv-contoso-prod"
   - Private Endpoints for SQL, Storage, Key Vault (inside snet-data)

5. **Monitoring**
   - Log Analytics Workspace: "law-contoso-prod"
   - Application Insights: "appi-contoso"

Connections:
- Users → Front Door → Application Gateway → Web App
- Web App → Order API
- Order API → SQL DB and Storage (private endpoints)
- Function App → Service Bus → SQL
- All apps → Key Vault for secrets
- All resources → Log Analytics
- All outbound traffic → Azure Firewall

Layout rules:
- Top: Users + Front Door
- Below: Application Gateway
- Middle: Web App + Backend API
- Right side: Function App + Service Bus
- Bottom: Data tier (SQL, Storage, Key Vault)
- Bottom left: Firewall
- Bottom centre: Monitoring resources
- Place everything inside a single VNet box with subnet boundaries.

Output format required:
- List each container (VNet, each subnet)
- List each resource with labels
- List the arrows and connections
- Make the layout instructions clear
- Use icons for every resource following the icon instructions above
