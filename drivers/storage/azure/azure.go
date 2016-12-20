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

	// DefaultMaxRetries is the max number of times to retry failed operations
	DefaultMaxRetries = 10

	// Config keys:
	// Authorization keys
	TenantIDKey       = "tenantID"
	ClientIDKey       = "clientID"
	ClientSecretKey   = "clientSecret"
	CertPathKey       = "certPath"

	// Storage auth keys
	StorageAccount    = "storageAccount"
	StorageAccessKey  = "storageAccessKey"
	// TODO: add option to pass StorageURI

	SubscriptionIDKey = "subscriptionID"
	ResourceGroupKey  = "resourceGroup"
	ContainerKey      = "container"
	MaxRetriesKey     = "maxRetries"
	TagKey            = "tag"
)

const (
	ConfigAZURE                     = Name
	ConfigAZURESubscriptionIDKey    = ConfigAZURE + "." + SubscriptionIDKey
	ConfigAZUREResourceGroupKey     = ConfigAZURE + "." + ResourceGroupKey
	ConfigAZURETenantIDKey          = ConfigAZURE + "." + TenantIDKey
	ConfigAZUREStorageAccountKey    = ConfigAZURE + "." + StorageAccount
	ConfigAZUREStorageAccessKeyKey  = ConfigAZURE + "." + StorageAccessKey
	ConfigAZUREContainerKey         = ConfigAZURE + "." + ContainerKey
	ConfigAZUREClientIDKey          = ConfigAZURE + "." + ClientIDKey
	ConfigAZUREClientSecretKey      = ConfigAZURE + "." + ClientSecretKey
	ConfigAZURECertPathKey          = ConfigAZURE + "." + CertPathKey
	ConfigAZUREMaxRetriesKey        = ConfigAZURE + "." + MaxRetriesKey
	ConfigAZURETagKey               = ConfigAZURE + "." + TagKey
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
	r.Key(gofig.Int, "", DefaultMaxRetries, "", ConfigAZUREMaxRetriesKey)
	r.Key(gofig.String, "", "", "Tag prefix for AZURE naming", ConfigAZURETagKey)

	gofigCore.Register(r)
}
