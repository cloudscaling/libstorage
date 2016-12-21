// +build !libstorage_storage_driver libstorage_storage_driver_azure

package storage

import (
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"hash"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"sync"
	//"time"

	gofig "github.com/akutz/gofig/types"
	"github.com/akutz/goof"

	autorestAzure "github.com/Azure/go-autorest/autorest/azure"
	armStorage "github.com/Azure/azure-sdk-for-go/arm/storage"
	blobStorage "github.com/Azure/azure-sdk-for-go/storage"
	//azureRest "github.com/Azure/go-autorest/autorest/azure"
	"golang.org/x/crypto/pkcs12"

	"github.com/codedellemc/libstorage/api/context"
	"github.com/codedellemc/libstorage/api/registry"
	"github.com/codedellemc/libstorage/api/types"
	"github.com/codedellemc/libstorage/drivers/storage/azure"
	azureUtils "github.com/codedellemc/libstorage/drivers/storage/azure/utils"
)

const (
	// waitVolumeCreate signifies to wait for volume creation to complete
	waitVolumeCreate = "create"
	// waitVolumeAttach signifies to wait for volume attachment to complete
	waitVolumeAttach = "attach"
	// waitVolumeDetach signifies to wait for volume detachment to complete
	waitVolumeDetach = "detach"
)

type driver struct {
	name             string
	config           gofig.Config
	subscriptionID   string
	resourceGroup    string
	tenantID         string
	storageAccount   string
	storageAccessKey string
	container        string
	clientID         string
	clientSecret     string
	certPath         string
	maxRetries       int
}

func init() {
	registry.RegisterStorageDriver(azure.Name, newDriver)
}

func newDriver() types.StorageDriver {
	return &driver{name: azure.Name}
}

func (d *driver) Name() string {
	return d.name
}

// Init initializes the driver.
func (d *driver) Init(context types.Context, config gofig.Config) error {
	d.config = config
	d.tenantID = d.getTenantID()
	d.clientID = d.getClientID()
	d.clientSecret = d.getClientSecret()
	d.certPath = d.getCertPath()
	d.maxRetries = d.getMaxRetries()

	d.storageAccount = d.getStorageAccount()
	d.storageAccessKey = d.getStorageAccessKey()
	d.container = d.getContainer()

	d.subscriptionID = d.getSubscriptionID()
	d.resourceGroup = d.getResourceGroup()

	d.maxRetries = d.getMaxRetries()

	context.Info("storage driver initialized")

	return nil
}

const cacheKeyC = "cacheKey"

type azureSession struct {
	accountClient		*armStorage.AccountsClient
	blobClient		*blobStorage.BlobStorageClient
}

var (
	sessions  = map[string]*azureSession{}
	sessionsL = &sync.Mutex{}
)

func writeHkeyB(h hash.Hash, ps []byte) {
	if ps == nil {
		return
	}
	h.Write(ps)
}

func writeHkey(h hash.Hash, ps *string) {
	writeHkeyB(h, []byte(*ps))
}

var (
	errLoginMsg = "Failed to login to Azure"
	errAuthFailed = goof.New(errLoginMsg)
	invalideRsaPrivateKey = goof.New("PKCS#12 certificate must contain an RSA private key")
)

func decodePkcs12(pkcs []byte, password string) (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, certificate, err := pkcs12.Decode(pkcs, password)
	if err != nil {
	return nil, nil, err
	}

	rsaPrivateKey, isRsaKey := privateKey.(*rsa.PrivateKey)
	if !isRsaKey {
	return nil, nil, invalideRsaPrivateKey
	}

	return certificate, rsaPrivateKey, nil
}

func mustSession(ctx types.Context) *azureSession {
	return context.MustSession(ctx).(*azureSession)
}

func (d *driver) Login(ctx types.Context) (interface{}, error) {
	sessionsL.Lock()
	defer sessionsL.Unlock()

	ctx.Debug("login to azure storage driver")
	var (
		hkey = md5.New()
		ckey string
		certData []byte
		spt *autorestAzure.ServicePrincipalToken
		err error
	)

	if d.tenantID == "" {
		return nil, goof.New("Empty tenantID") 
	}

	writeHkey(hkey, &d.subscriptionID)
	writeHkey(hkey, &d.resourceGroup)
	writeHkey(hkey, &d.tenantID)
	writeHkey(hkey, &d.storageAccount)
	writeHkey(hkey, &d.storageAccessKey)
	if d.clientID != "" && d.clientSecret != "" {
		ctx.Debug("login to azure storage driver using clientID and clientSecret")
		writeHkey(hkey, &d.clientID)
		writeHkey(hkey, &d.clientSecret)
	} else if d.certPath != "" {
		ctx.Debug("login to azure storage driver using clientCert")
		// TODO: impl reading of cert
		// TODO: impl for cert
		certData, err = ioutil.ReadFile(d.certPath)
		if err != nil {
			return nil, goof.WithError("Failed to read provided certificate file", err)
		}
		writeHkeyB(hkey, certData)
	} else {
		ctx.Error("No login information provided")
		return nil, errAuthFailed
	}
	ckey = fmt.Sprintf("%x", hkey.Sum(nil))

	if session, ok := sessions[ckey]; ok {
		ctx.WithField(cacheKeyC, ckey).Debug("using cached azure client")
		return session, nil
	}

	oauthConfig, err := autorestAzure.PublicCloud.OAuthConfigForTenant(d.tenantID)
	if err != nil {
		return nil, goof.WithError("Failed to create OAuthConfig for tenant", err)
	}

	if d.clientID != "" && d.clientSecret != "" {
		spt, err = autorestAzure.NewServicePrincipalToken(*oauthConfig, d.clientID,
			d.clientSecret, autorestAzure.PublicCloud.ResourceManagerEndpoint)
		if err != nil {
			return nil, goof.WithError("Failed to create Service Principal Token with client ID and secret", err)
		}
	} else {
		certificate, rsaPrivateKey, err := decodePkcs12(certData, "")
		if err != nil {
			return nil, goof.WithError("Failed to decode certificate data", err)
		}

		spt, err = autorestAzure.NewServicePrincipalTokenFromCertificate(*oauthConfig,
			d.clientID, certificate, rsaPrivateKey,
			autorestAzure.PublicCloud.ResourceManagerEndpoint)
		if err != nil {
			return nil, goof.WithError("Failed to create Service Principal Token with certificate ", err)
		}
	}

	newAC := armStorage.NewAccountsClient(d.subscriptionID)
	newAC.Authorizer = spt
	bc, err := blobStorage.NewBasicClient(d.storageAccount, d.storageAccessKey)
	 if err != nil {
		return nil, goof.WithError("Failed to create BlobStorage client", err)
	}
	newBC := bc.GetBlobService()
	session := azureSession{
		accountClient: &newAC,
		blobClient: &newBC,
	}
	sessions[ckey] = &session

	ctx.WithField(cacheKeyC, ckey).Info("login to azure storage driver created and cached")

	return &session, nil
}

// NextDeviceInfo returns the information about the driver's next available
// device workflow.
func (d *driver) NextDeviceInfo(
	ctx types.Context) (*types.NextDeviceInfo, error) {
	return azureUtils.NextDeviceInfo, nil
}

// Type returns the type of storage the driver provides.
func (d *driver) Type(ctx types.Context) (types.StorageType, error) {
	//Example: Block storage
	return types.Block, nil
}

// InstanceInspect returns an instance.
func (d *driver) InstanceInspect(
	ctx types.Context,
	opts types.Store) (*types.Instance, error) {

	iid := context.MustInstanceID(ctx)
	return &types.Instance{
		Name:	 iid.ID,
		//Region:       iid.Fields[azure.InstanceIDFieldRegion],
		InstanceID:   iid,
		ProviderName: iid.Driver,
	}, nil
}

// Volumes returns all volumes or a filtered list of volumes.
func (d *driver) Volumes(
	ctx types.Context,
	opts *types.VolumesOpts) ([]*types.Volume, error) {

	list, err := mustSession(ctx).blobClient.ListBlobs(d.container, blobStorage.ListBlobsParameters{})

	if err != nil {
		return nil, goof.WithError("error listing blobs", err)
	}
	// Convert retrieved volumes to libStorage types.Volume
	vols, convErr := d.toTypesVolume(ctx, &list.Blobs, opts.Attachments)
	if convErr != nil {
		return nil, goof.WithError("error converting to types.Volume", convErr)
	}
	return vols, nil
}

// VolumeInspect inspects a single volume.
func (d *driver) VolumeInspect(
	ctx types.Context,
	volumeID string,
	opts *types.VolumeInspectOpts) (*types.Volume, error) {
	// TODO: impl
	return nil, types.ErrNotImplemented
}

// VolumeCreate creates a new volume.
func (d *driver) VolumeCreate(ctx types.Context, volumeName string,
	opts *types.VolumeCreateOpts) (*types.Volume, error) {
	// Initialize for logging
	// TODO: impl
	return nil, types.ErrNotImplemented
}

// VolumeCreateFromSnapshot creates a new volume from an existing snapshot.
func (d *driver) VolumeCreateFromSnapshot(
	ctx types.Context,
	snapshotID, volumeName string,
	opts *types.VolumeCreateOpts) (*types.Volume, error) {
	// TODO Snapshots are not implemented yet
	return nil, types.ErrNotImplemented
}

// VolumeCopy copies an existing volume.
func (d *driver) VolumeCopy(
	ctx types.Context,
	volumeID, volumeName string,
	opts types.Store) (*types.Volume, error) {
	// TODO Snapshots are not implemented yet
	return nil, types.ErrNotImplemented
}

// VolumeSnapshot snapshots a volume.
func (d *driver) VolumeSnapshot(
	ctx types.Context,
	volumeID, snapshotName string,
	opts types.Store) (*types.Snapshot, error) {
	// TODO Snapshots are not implemented yet
	return nil, types.ErrNotImplemented
}

// VolumeRemove removes a volume.
func (d *driver) VolumeRemove(
	ctx types.Context,
	volumeID string,
	opts types.Store) error {

	//TODO check if volume is attached? if so fail
	// TODO: impl
	return types.ErrNotImplemented
}

// VolumeAttach attaches a volume and provides a token clients can use
// to validate that device has appeared locally.
func (d *driver) VolumeAttach(
	ctx types.Context,
	volumeID string,
	opts *types.VolumeAttachOpts) (*types.Volume, string, error) {
	// TODO: impl
	return nil, "", types.ErrNotImplemented
}

var errVolAlreadyDetached = goof.New("volume already detached")

// VolumeDetach detaches a volume.
func (d *driver) VolumeDetach(
	ctx types.Context,
	volumeID string,
	opts *types.VolumeDetachOpts) (*types.Volume, error) {
	// TODO: impl
	return nil, types.ErrNotImplemented
}

// Snapshots returns all volumes or a filtered list of snapshots.
func (d *driver) Snapshots(
	ctx types.Context,
	opts types.Store) ([]*types.Snapshot, error) {
	// TODO Snapshots are not implemented yet
	return nil, types.ErrNotImplemented
}

// SnapshotInspect inspects a single snapshot.
func (d *driver) SnapshotInspect(
	ctx types.Context,
	snapshotID string,
	opts types.Store) (*types.Snapshot, error) {
	// TODO Snapshots are not implemented yet
	return nil, types.ErrNotImplemented
}

// SnapshotCopy copies an existing snapshot.
func (d *driver) SnapshotCopy(
	ctx types.Context,
	snapshotID, snapshotName, destinationID string,
	opts types.Store) (*types.Snapshot, error) {
	// TODO Snapshots are not implemented yet
	return nil, types.ErrNotImplemented
}

// SnapshotRemove removes a snapshot.
func (d *driver) SnapshotRemove(
	ctx types.Context,
	snapshotID string,
	opts types.Store) error {
	// TODO Snapshots are not implemented yet
	return types.ErrNotImplemented
}


// Get volume or snapshot name without config tag
func (d *driver) getPrintableName(name string) string {
	return strings.TrimPrefix(name, d.tag() + azure.TagDelimiter)
}

// Prefix volume or snapshot name with config tag
func (d *driver) getFullName(name string) string {
	if d.tag() != "" {
		return d.tag() + azure.TagDelimiter + name
	}
	return name
}

// Retrieve config arguments
func (d *driver) getSubscriptionID() string {
	if result := os.Getenv("AZURE_SUBSCRIPTION_ID"); result != "" {
		return result
	}
	return d.config.GetString(azure.ConfigAZURESubscriptionIDKey)
}

func (d *driver) getResourceGroup() string {
	if result := os.Getenv("AZURE_RESOURCE_GROUP"); result != "" {
		return result
	}
	return d.config.GetString(azure.ConfigAZUREResourceGroupKey)
}

func (d *driver) getTenantID() string {
	if result := os.Getenv("AZURE_TENANT_ID"); result != "" {
		return result
	}
	return d.config.GetString(azure.ConfigAZURETenantIDKey)
}

func (d *driver) getStorageAccount() string {
	if result := os.Getenv("AZURE_STORAGE_ACCOUNT"); result != "" {
		return result
	}
	return d.config.GetString(azure.ConfigAZUREStorageAccountKey)
}

func (d *driver) getStorageAccessKey() string {
	if result := os.Getenv("AZURE_STORAGE_ACCESS_KEY"); result != "" {
		return result
	}
	return d.config.GetString(azure.ConfigAZUREStorageAccessKeyKey)
}

func (d *driver) getContainer() string {
	if result := os.Getenv("AZURE_CONTAINER"); result != "" {
	return result
	}
	return d.config.GetString(azure.ConfigAZUREContainerKey)
}

func (d *driver) getClientID() string {
	if result := os.Getenv("AZURE_CLIENT_ID"); result != "" {
		return result
	}
	return d.config.GetString(azure.ConfigAZUREClientIDKey)
}

func (d *driver) getClientSecret() string {
	if result := os.Getenv("AZURE_CLIENT_SECRET"); result != "" {
		return result
	}
	return d.config.GetString(azure.ConfigAZUREClientSecretKey)
}

func (d *driver) getCertPath() string {
	if result := os.Getenv("AZURE_CERT_PATH"); result != "" {
		return result
	}
	return d.config.GetString(azure.ConfigAZURECertPathKey)
}

func (d *driver) getMaxRetries() int {
	return d.config.GetInt(azure.ConfigAZUREMaxRetriesKey)
}

func (d *driver) tag() string {
	return d.config.GetString(azure.ConfigAZURETagKey)
}

// TODO rexrayTag
/*func (d *driver) rexrayTag() string {
  return d.config.GetString("azure.rexrayTag")
}*/

var errGetLocDevs = goof.New("error getting local devices from context")

var extRX = regexp.MustCompile(".*\\.vhd$")

func (d *driver) toTypesVolume(
	ctx types.Context,
	blobs *[]blobStorage.Blob,
	attachments types.VolumeAttachmentsTypes) ([]*types.Volume, error) {

/*        var (
		ld *types.LocalDevices
		ldOK bool
	)

	if attachments.Devices() {
		// Get local devices map from context
		if ld, ldOK = context.LocalDevices(ctx); !ldOK {
			return nil, errGetLocDevs
		}
	}
*/

	var volumesSD []*types.Volume
	for _, blob := range *blobs {
//		if blob.Properties.BlobType == blobStorage.BlobTypePage || blob.Properties.BlobType == "" {
		if extRX.MatchString(blob.Name) {
			var attachmentsSD []*types.VolumeAttachment
			if attachments.Requested() {
// TODO:
//				return nil, types.ErrNotImplemented 
			}
			volumeSD := &types.Volume{
				Name:             blob.Name,
				ID:               blob.Name,
// TODO:
//				AvailabilityZone: *volume.AvailabilityZone,
//				Encrypted:        *volume.Encrypted,
//				Status:           *volume.State,
//				Type:             *volume.VolumeType,
				Size:             blob.Properties.ContentLength,
				Attachments:      attachmentsSD,
			}

			// Some volume types have no IOPS, so we get nil in volume.Iops
//			if volume.Iops != nil {
//				volumeSD.IOPS = *volume.Iops
//			}
			volumesSD = append(volumesSD, volumeSD)
		}
	}
	return volumesSD, nil
}
