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
	SubscriptionIDKey = "subscriptionID"
	ResourceGroupKey  = "resourceGroup"
	TenantIDKey       = "tenantID"
	StorageAccountKey = "storageAccount"
	ContainerKey      = "container"
	ClientIDKey       = "clientID"
	ClientSecretKey   = "clientSecret"
	CertPathKey       = "certPath"
	MaxRetriesKey     = "maxRetries"
	TagKey            = "tag"
)

const (
	ConfigAZURE                  = Name
	ConfigAZURESubscriptionIDKey = ConfigAZURE + "." + SubscriptionIDKey
	ConfigAZUREResourceGroupKey  = ConfigAZURE + "." + ResourceGroupKey
	ConfigAZURETenantIDKey       = ConfigAZURE + "." + TenantIDKey
	ConfigAZUREStorageAccountKey = ConfigAZURE + "." + StorageAccountKey
	ConfigAZUREContainerKey      = ConfigAZURE + "." + ContainerKey
	ConfigAZUREClientIDKey       = ConfigAZURE + "." + ClientIDKey
	ConfigAZUREClientSecretKey   = ConfigAZURE + "." + ClientSecretKey
	ConfigAZURECertPathKey       = ConfigAZURE + "." + CertPathKey
	ConfigAZUREMaxRetriesKey     = ConfigAZURE + "." + MaxRetriesKey
	ConfigAZURETagKey            = ConfigAZURE + "." + TagKey
)

func init() {
	r := gofigCore.NewRegistration("AZURE")
	r.Key(gofig.String, "", "", "", Name+"."+SubscriptionIDKey)
	r.Key(gofig.String, "", "", "", Name+"."+ResourceGroupKey)
	r.Key(gofig.String, "", "", "", Name+"."+TenantIDKey)
	r.Key(gofig.String, "", "", "", Name+"."+StorageAccountKey)
	r.Key(gofig.String, "", "", "", Name+"."+ContainerKey)
	r.Key(gofig.String, "", "", "", Name+"."+ClientIDKey)
	r.Key(gofig.String, "", "", "", Name+"."+ClientSecretKey)
	r.Key(gofig.String, "", "", "", Name+"."+CertPathKey)
	r.Key(gofig.Int, "", DefaultMaxRetries, "", Name+"."+MaxRetriesKey)
	r.Key(gofig.String, "", "", "Tag prefix for AZURE naming", Name+"."+TagKey)

	gofigCore.Register(r)
}
