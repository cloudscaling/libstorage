// +build !libstorage_storage_driver libstorage_storage_driver_azure

package azure

import (
	gofigCore "github.com/akutz/gofig"
	gofig "github.com/akutz/gofig/types"
)

const (
	// Name is the provider's name.
	Name = "azure"

	// TagDelimiter separates tags from volume or snapshot names
	TagDelimiter = "/"

	// DefaultUseHTTPS - Use https prefix by default
	// or not for Azure URI's
	DefaultUseHTTPS = true

	// TenantIDKey is a Directory ID from Azure
	TenantIDKey = "tenantID"
	// ClientIDKey is an Application ID from Azure
	ClientIDKey = "clientID"
	// ClientSecretKey is a secret of the application
	ClientSecretKey = "clientSecret"
	// CertPathKey is a path to application certificate in case of
	// authorization via certificate
	CertPathKey = "certPath"

	// StorageAccount is a name of storage account
	StorageAccount = "storageAccount"
	// StorageAccessKey is an access key of storage account
	StorageAccessKey = "storageAccessKey"
	// TODO: add option to pass StorageURI

	// SubscriptionIDKey is an ID of subscription
	SubscriptionIDKey = "subscriptionID"
	// ResourceGroupKey is a name of resource group
	ResourceGroupKey = "resourceGroup"
	// ContainerKey is a name of container in the storage account
	// ('vhds' by default)
	ContainerKey = "container"
	// UseHTTPS is a flag about use https or not for making Azure URI's
	UseHTTPSKey = "useHTTPS"
	// TagKey is a tag key
	TagKey = "tag"
)

const (
	// ConfigAZURE is a config key
	ConfigAZURE = Name

	// ConfigAZURESubscriptionIDKey is a config key
	ConfigAZURESubscriptionIDKey = ConfigAZURE + "." + SubscriptionIDKey

	// ConfigAZUREResourceGroupKey is a config key
	ConfigAZUREResourceGroupKey = ConfigAZURE + "." + ResourceGroupKey

	// ConfigAZURETenantIDKey is a config key
	ConfigAZURETenantIDKey = ConfigAZURE + "." + TenantIDKey

	// ConfigAZUREStorageAccountKey is a config key
	ConfigAZUREStorageAccountKey = ConfigAZURE + "." + StorageAccount

	// ConfigAZUREStorageAccessKeyKey is a config key
	ConfigAZUREStorageAccessKeyKey = ConfigAZURE + "." + StorageAccessKey

	// ConfigAZUREContainerKey is a config key
	ConfigAZUREContainerKey = ConfigAZURE + "." + ContainerKey

	// ConfigAZUREClientIDKey is a config key
	ConfigAZUREClientIDKey = ConfigAZURE + "." + ClientIDKey

	// ConfigAZUREClientSecretKey is a config key
	ConfigAZUREClientSecretKey = ConfigAZURE + "." + ClientSecretKey

	// ConfigAZURECertPathKey is a config key
	ConfigAZURECertPathKey = ConfigAZURE + "." + CertPathKey

	// ConfigAZUREUseHTTPSKey is a config key
	ConfigAZUREUseHTTPSKey = ConfigAZURE + "." + UseHTTPSKey

	// ConfigAZURETagKey is a config key
	ConfigAZURETagKey = ConfigAZURE + "." + TagKey
)

func init() {
	r := gofigCore.NewRegistration("AZURE")
	r.Key(gofig.String, "", "", "", ConfigAZURESubscriptionIDKey)
	r.Key(gofig.String, "", "", "", ConfigAZUREResourceGroupKey)
	r.Key(gofig.String, "", "", "", ConfigAZURETenantIDKey)
	r.Key(gofig.String, "", "", "", ConfigAZUREStorageAccountKey)
	r.Key(gofig.String, "", "", "", ConfigAZUREContainerKey)
	r.Key(gofig.String, "", "", "", ConfigAZUREClientIDKey)
	r.Key(gofig.String, "", "", "", ConfigAZUREClientSecretKey)
	r.Key(gofig.String, "", "", "", ConfigAZURECertPathKey)
	r.Key(gofig.Bool, "", DefaultUseHTTPS, "", ConfigAZUREUseHTTPSKey)
	r.Key(gofig.String, "", "",
		"Tag prefix for AZURE naming", ConfigAZURETagKey)

	gofigCore.Register(r)
}
