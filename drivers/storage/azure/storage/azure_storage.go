// +build !libstorage_storage_driver libstorage_storage_driver_azure

package storage

import (
	//"crypto/md5"
	//"fmt"
	"hash"
	"os"
	"strings"
	"sync"
	//"time"

	log "github.com/Sirupsen/logrus"

	gofig "github.com/akutz/gofig/types"
	"github.com/akutz/goof"

	"github.com/Azure/azure-sdk-for-go/arm/storage"
	//azureRest "github.com/Azure/go-autorest/autorest/azure"

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
	d.subscriptionID = d.getSubscriptionID()
	d.resourceGroup = d.getResourceGroup()
	d.tenantID = d.getTenantID()
	d.storageAccount = d.getStorageAccount()
	d.clientID = d.getClientID()
	d.clientSecret = d.getClientSecret()
	d.certPath = d.getCertPath()

	//maxRetries := d.getMaxRetries()
	//d.maxRetries = &maxRetries

	log.Info("storage driver initialized")
	return nil
}

const cacheKeyC = "cacheKey"

var (
	sessions  = map[string]*storage.AccountsClient{}
	sessionsL = &sync.Mutex{}
)

func writeHkey(h hash.Hash, ps *string) {
	if ps == nil {
		return
	}
	h.Write([]byte(*ps))
}

func (d *driver) Login(ctx types.Context) (interface{}, error) {
	sessionsL.Lock()
	defer sessionsL.Unlock()

	// TODO: impl
	return nil, types.ErrNotImplemented
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
		Name:         iid.ID,
		//Region:       iid.Fields[azure.InstanceIDFieldRegion],
		InstanceID:   iid,
		ProviderName: iid.Driver,
	}, nil
}

// Volumes returns all volumes or a filtered list of volumes.
func (d *driver) Volumes(
	ctx types.Context,
	opts *types.VolumesOpts) ([]*types.Volume, error) {
	// TODO: impl
	return nil, types.ErrNotImplemented
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
