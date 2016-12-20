// +build !libstorage_storage_driver libstorage_storage_driver_azure

package storage

import (
	"crypto/md5"
	"fmt"
	"hash"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"

	gofig "github.com/akutz/gofig/types"
	"github.com/akutz/goof"

	"github.com/Azure/azure-sdk-for-go/arm/storage"
	"github.com/Azure/go-autorest/autorest/azure"

	"github.com/codedellemc/libstorage/api/context"
	"github.com/codedellemc/libstorage/api/registry"
	"github.com/codedellemc/libstorage/api/types"
	"github.com/codedellemc/libstorage/drivers/storage/azure"
	"github.com/codedellemc/libstorage/drivers/storage/ebs"
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

	maxRetries := d.getMaxRetries()
	d.maxRetries = &maxRetries
	
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

	var (
		endpoint *string
		ckey     string
		hkey     = md5.New()
		akey     = d.accessKey
		region   = d.mustRegion(ctx)
	)

	if region != nil {
		szEndpint := fmt.Sprintf("ec2.%s.amazonaws.com", *region)
		endpoint = &szEndpint
	} else {
		endpoint = d.endpoint
	}

	writeHkey(hkey, region)
	writeHkey(hkey, endpoint)
	writeHkey(hkey, &akey)
	ckey = fmt.Sprintf("%x", hkey.Sum(nil))

	// if the session is cached then return it
	if svc, ok := sessions[ckey]; ok {
		log.WithField(cacheKeyC, ckey).Debug("using cached azure service")
		return svc, nil
	}

	var (
		skey   = d.secretKey()
		fields = map[string]interface{}{
			ebs.AccessKey: akey,
			ebs.Tag:       d.tag(),
			cacheKeyC:     ckey,
		}
	)

	if skey == "" {
		fields[ebs.SecretKey] = ""
	} else {
		fields[ebs.SecretKey] = "******"
	}
	if region != nil {
		fields[ebs.Region] = *region
	}
	if endpoint != nil {
		fields[ebs.Endpoint] = *endpoint
	}

	log.WithFields(fields).Debug("ebs service connetion attempt")
	sess := session.New()

	svc := awsec2.New(
		sess,
		&aws.Config{
			Region:     region,
			Endpoint:   endpoint,
			MaxRetries: d.maxRetries,
			Credentials: credentials.NewChainCredentials(
				[]credentials.Provider{
					&credentials.StaticProvider{
						Value: credentials.Value{
							AccessKeyID:     akey,
							SecretAccessKey: skey,
						},
					},
					&credentials.EnvProvider{},
					&credentials.SharedCredentialsProvider{},
					&ec2rolecreds.EC2RoleProvider{
						Client: ec2metadata.New(sess),
					},
				},
			),
		},
	)

	sessions[ckey] = svc
	log.WithFields(fields).Info("azure storage client created & cached")

	return svc, nil
}

func mustSession(ctx types.Context) *awsec2.EC2 {
	return context.MustSession(ctx).(*awsec2.EC2)
}

func mustInstanceIDID(ctx types.Context) *string {
	return &context.MustInstanceID(ctx).ID
}

func (d *driver) mustRegion(ctx types.Context) *string {
	if iid, ok := context.InstanceID(ctx); ok {
		if v, ok := iid.Fields[ebs.InstanceIDFieldRegion]; ok && v != "" {
			return &v
		}
	}
	return d.region
}

func (d *driver) mustAvailabilityZone(ctx types.Context) *string {
	if iid, ok := context.InstanceID(ctx); ok {
		if v, ok := iid.Fields[ebs.InstanceIDFieldAvailabilityZone]; ok {
			if v != "" {
				return &v
			}
		}
	}
	return nil
}

// NextDeviceInfo returns the information about the driver's next available
// device workflow.
func (d *driver) NextDeviceInfo(
	ctx types.Context) (*types.NextDeviceInfo, error) {
	return ebsUtils.NextDeviceInfo, nil
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
		Region:       iid.Fields[ebs.InstanceIDFieldRegion],
		InstanceID:   iid,
		ProviderName: iid.Driver,
	}, nil
}

// Volumes returns all volumes or a filtered list of volumes.
func (d *driver) Volumes(
	ctx types.Context,
	opts *types.VolumesOpts) ([]*types.Volume, error) {
	// Get all volumes via EC2 API
	ec2vols, err := d.getVolume(ctx, "", "")
	if err != nil {
		return nil, goof.WithError("error getting volume", err)
	}
	if len(ec2vols) == 0 {
		return nil, errNoVolReturned
	}
	// Convert retrieved volumes to libStorage types.Volume
	vols, convErr := d.toTypesVolume(ctx, ec2vols, opts.Attachments)
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
	// Get volume corresponding to volume ID via EC2 API
	ec2vols, err := d.getVolume(ctx, volumeID, "")
	if err != nil {
		return nil, goof.WithError("error getting volume", err)
	}
	if len(ec2vols) == 0 {
		return nil, errNoVolReturned
	}
	vols, convErr := d.toTypesVolume(ctx, ec2vols, opts.Attachments)
	if convErr != nil {
		return nil, goof.WithError("error converting to types.Volume", convErr)
	}

	// Because getVolume returns an array
	// and we only expect the 1st element to be a match, return 1st element
	return vols[0], nil
}

// VolumeCreate creates a new volume.
func (d *driver) VolumeCreate(ctx types.Context, volumeName string,
	opts *types.VolumeCreateOpts) (*types.Volume, error) {
	// Initialize for logging
	fields := map[string]interface{}{
		"driverName": d.Name(),
		"volumeName": volumeName,
		"opts":       opts,
	}

	log.WithFields(fields).Debug("creating volume")

	// Check if volume with same name exists
	ec2vols, err := d.getVolume(ctx, "", volumeName)
	if err != nil {
		return nil, goof.WithFieldsE(fields, "error getting volume", err)
	}
	volumes, convErr := d.toTypesVolume(ctx, ec2vols, 0)
	if convErr != nil {
		return nil, goof.WithFieldsE(
			fields, "error converting to types.Volume", convErr)
	}

	if len(volumes) > 0 {
		return nil, goof.WithFields(fields, "volume name already exists")
	}

	// Pass libStorage types.Volume to helper function which calls EC2 API
	vol, err := d.createVolume(ctx, volumeName, "", opts)
	if err != nil {
		return nil, goof.WithFieldsE(fields, "error creating volume", err)
	}
	// Return the volume created
	return d.VolumeInspect(ctx, *vol.VolumeId, &types.VolumeInspectOpts{
		Attachments: types.VolAttReqTrue,
	})
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
	// Initialize for logging
	fields := map[string]interface{}{
		"provider": d.Name(),
		"volumeID": volumeID,
	}

	//TODO check if volume is attached? if so fail

	// Delete volume via EC2 API call
	dvInput := &awsec2.DeleteVolumeInput{
		VolumeId: &volumeID,
	}
	_, err := mustSession(ctx).DeleteVolume(dvInput)
	if err != nil {
		return goof.WithFieldsE(fields, "error deleting volume", err)
	}

	return nil
}

var (
	errMissingNextDevice  = goof.New("missing next device")
	errVolAlreadyAttached = goof.New("volume already attached to a host")
)

// VolumeAttach attaches a volume and provides a token clients can use
// to validate that device has appeared locally.
func (d *driver) VolumeAttach(
	ctx types.Context,
	volumeID string,
	opts *types.VolumeAttachOpts) (*types.Volume, string, error) {
	// review volume with attachments to any host
	ec2vols, err := d.getVolume(ctx, volumeID, "")
	if err != nil {
		return nil, "", goof.WithError("error getting volume", err)
	}
	volumes, convErr := d.toTypesVolume(
		ctx, ec2vols, types.VolAttReqTrue)
	if convErr != nil {
		return nil, "", goof.WithError(
			"error converting to types.Volume", convErr)
	}

	// Check if there a volume to attach
	if len(volumes) == 0 {
		return nil, "", goof.New("no volume found")
	}
	// Check if volume is already attached
	if len(volumes[0].Attachments) > 0 {
		// Detach already attached volume if forced
		if !opts.Force {
			return nil, "", errVolAlreadyAttached
		}
		_, err := d.VolumeDetach(
			ctx,
			volumeID,
			&types.VolumeDetachOpts{
				Force: opts.Force,
				Opts:  opts.Opts,
			})
		if err != nil {
			return nil, "", goof.WithError("error detaching volume", err)
		}
	}

	if opts.NextDevice == nil {
		return nil, "", errMissingNextDevice
	}

	// Attach volume via helper function which uses EC2 API call
	err = d.attachVolume(ctx, volumeID, volumes[0].Name, *opts.NextDevice)
	if err != nil {
		return nil, "", goof.WithFieldsE(
			log.Fields{
				"provider": d.Name(),
				"volumeID": volumeID},
			"error attaching volume",
			err,
		)
	}

	// Wait for volume's status to update
	if err = d.waitVolumeComplete(ctx, volumeID, waitVolumeAttach); err != nil {
		return nil, "", goof.WithError("error waiting for volume attach", err)
	}

	// Check if successful attach
	attachedVol, err := d.VolumeInspect(
		ctx, volumeID, &types.VolumeInspectOpts{
			Attachments: types.VolAttReqTrue,
			Opts:        opts.Opts,
		})
	if err != nil {
		return nil, "", goof.WithError("error getting volume", err)
	}

	// Token is the attachment's device name, which will be matched
	// to the executor's device ID
	return attachedVol, *opts.NextDevice, nil
}

var errVolAlreadyDetached = goof.New("volume already detached")

// VolumeDetach detaches a volume.
func (d *driver) VolumeDetach(
	ctx types.Context,
	volumeID string,
	opts *types.VolumeDetachOpts) (*types.Volume, error) {
	// review volume with attachments to any host
	ec2vols, err := d.getVolume(ctx, volumeID, "")
	if err != nil {
		return nil, goof.WithError("error getting volume", err)
	}
	volumes, convErr := d.toTypesVolume(
		ctx, ec2vols, types.VolAttReqTrue)
	if convErr != nil {
		return nil, goof.WithError("error converting to types.Volume", convErr)
	}

	// no volumes to detach
	if len(volumes) == 0 {
		return nil, errNoVolReturned
	}

	// volume has no attachments
	if len(volumes[0].Attachments) == 0 {
		return nil, errVolAlreadyDetached
	}

	dvInput := &awsec2.DetachVolumeInput{
		VolumeId: &volumeID,
		Force:    &opts.Force,
	}

	// Detach volume using EC2 API call
	if _, err = mustSession(ctx).DetachVolume(dvInput); err != nil {
		return nil, goof.WithFieldsE(
			log.Fields{
				"provider": d.Name(),
				"volumeID": volumeID}, "error detaching volume", err)
	}

	if err = d.waitVolumeComplete(ctx, volumeID, waitVolumeDetach); err != nil {
		return nil, goof.WithError("error waiting for volume detach", err)
	}

	ctx.Info("detached volume", volumeID)

	// check if successful detach
	detachedVol, err := d.VolumeInspect(
		ctx, volumeID, &types.VolumeInspectOpts{
			Attachments: types.VolAttReqTrue,
			Opts:        opts.Opts,
		})
	if err != nil {
		return nil, goof.WithError("error getting volume", err)
	}

	return detachedVol, nil
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

///////////////////////////////////////////////////////////////////////
/////////        HELPER FUNCTIONS SPECIFIC TO PROVIDER        /////////
///////////////////////////////////////////////////////////////////////
// getVolume searches for and returns volumes matching criteria
func (d *driver) getVolume(
	ctx types.Context,
	volumeID, volumeName string) ([]*awsec2.Volume, error) {

	// prepare filters
	filters := []*awsec2.Filter{}

	if avaiZone := d.mustAvailabilityZone(ctx); avaiZone != nil {
		filters = append(filters, &awsec2.Filter{
			Name:   aws.String("availability-zone"),
			Values: []*string{avaiZone},
		})
	}

	if volumeName != "" {
		filters = append(filters, &awsec2.Filter{
			Name: aws.String("tag:Name"), Values: []*string{&volumeName}})
	}

	if volumeID != "" {
		filters = append(filters, &awsec2.Filter{
			Name: aws.String("volume-id"), Values: []*string{&volumeID}})
	}

	// TODO rexrayTag
	/*  if d.ec2Tag != "" {
	      filters = append(filters, &awsec2.Filter{
	        Name:   aws.String(fmt.Sprintf("tag:%s", d.rexrayTag())),
	        Values: []*string{&d.ec2Tag}})
	    }
	*/
	// Prepare input
	dvInput := &awsec2.DescribeVolumesInput{}

	// Apply filters if arguments are specified
	if len(filters) > 0 {
		dvInput.Filters = filters
	}

	if volumeID != "" {
		dvInput.VolumeIds = []*string{&volumeID}
	}

	// Retrieve filtered volumes through EC2 API call
	resp, err := mustSession(ctx).DescribeVolumes(dvInput)
	if err != nil {
		return []*awsec2.Volume{}, err
	}

	return resp.Volumes, nil
}

var errGetLocDevs = goof.New("error getting local devices from context")

// Converts EC2 API volumes to libStorage types.Volume
func (d *driver) toTypesVolume(
	ctx types.Context,
	ec2vols []*awsec2.Volume,
	attachments types.VolumeAttachmentsTypes) ([]*types.Volume, error) {

	var (
		ld   *types.LocalDevices
		ldOK bool
	)

	if attachments.Devices() {
		// Get local devices map from context
		if ld, ldOK = context.LocalDevices(ctx); !ldOK {
			return nil, errGetLocDevs
		}
	}

	var volumesSD []*types.Volume
	for _, volume := range ec2vols {

		var attachmentsSD []*types.VolumeAttachment
		if attachments.Requested() {
			// Leave attachment's device name blank if attachments is false
			for _, attachment := range volume.Attachments {
				deviceName := ""
				if attachments.Devices() {
					// Compensate for kernel volume mapping i.e. change
					// "/dev/sda" to "/dev/xvda"
					deviceName = strings.Replace(
						*attachment.Device, "sd",
						ebsUtils.NextDeviceInfo.Prefix, 1)
					// Keep device name if it is found in local devices
					if _, ok := ld.DeviceMap[deviceName]; !ok {
						deviceName = ""
					}
				}
				attachmentSD := &types.VolumeAttachment{
					VolumeID: *attachment.VolumeId,
					InstanceID: &types.InstanceID{
						ID:     *attachment.InstanceId,
						Driver: d.Name(),
					},
					DeviceName: deviceName,
					Status:     *attachment.State,
				}
				attachmentsSD = append(attachmentsSD, attachmentSD)
			}
		}

		name := d.getName(volume.Tags)
		volumeSD := &types.Volume{
			Name:             name,
			ID:               *volume.VolumeId,
			AvailabilityZone: *volume.AvailabilityZone,
			Encrypted:        *volume.Encrypted,
			Status:           *volume.State,
			Type:             *volume.VolumeType,
			Size:             *volume.Size,
			Attachments:      attachmentsSD,
		}

		// Some volume types have no IOPS, so we get nil in volume.Iops
		if volume.Iops != nil {
			volumeSD.IOPS = *volume.Iops
		}
		volumesSD = append(volumesSD, volumeSD)
	}
	return volumesSD, nil
}

var (
	errNoVolReturned       = goof.New("no volume returned")
	errTooManyVolsReturned = goof.New("too many volumes returned")
)

// Used in VolumeAttach
func (d *driver) attachVolume(
	ctx types.Context,
	volumeID, volumeName, deviceName string) error {

	// sanity check # of volumes to attach
	vol, err := d.getVolume(ctx, volumeID, volumeName)
	if err != nil {
		return goof.WithError("error getting volume", err)
	}

	if len(vol) == 0 {
		return errNoVolReturned
	}
	if len(vol) > 1 {
		return errTooManyVolsReturned
	}

	// Attach volume via EC2 API call
	avInput := &awsec2.AttachVolumeInput{
		Device:     &deviceName,
		InstanceId: mustInstanceIDID(ctx),
		VolumeId:   &volumeID,
	}

	if _, err := mustSession(ctx).AttachVolume(avInput); err != nil {
		return err
	}
	return nil
}

// Used in VolumeCreate
func (d *driver) createVolume(
	ctx types.Context,
	volumeName, snapshotID string,
	opts *types.VolumeCreateOpts) (*awsec2.Volume, error) {

	var (
		err    error
		server awsec2.Instance
	)
	// Create volume using EC2 API call
	if server, err = d.getInstance(ctx); err != nil {
		return &awsec2.Volume{}, goof.WithError(
			"error creating volume with EC2 API call", err)
	}

	// Fill in Availability Zone if needed
	d.createVolumeEnsureAvailabilityZone(opts.AvailabilityZone, &server)

	options := &awsec2.CreateVolumeInput{
		Size:             opts.Size,
		AvailabilityZone: opts.AvailabilityZone,
		Encrypted:        opts.Encrypted,
		VolumeType:       opts.Type,
	}
	if snapshotID != "" {
		options.SnapshotId = &snapshotID
	}
	if opts.IOPS != nil && *opts.IOPS > 0 {
		options.Iops = opts.IOPS
	}
	if opts.Encrypted != nil && *opts.Encrypted {
		if opts.EncryptionKey != nil && len(*opts.EncryptionKey) > 0 {
			ctx.Debug("creating encrypted volume w client enc key")
			options.KmsKeyId = opts.EncryptionKey
		} else if len(d.kmsKeyID) > 0 {
			ctx.Debug("creating encrypted volume w server enc key")
			options.KmsKeyId = aws.String(d.kmsKeyID)
		} else {
			ctx.Debug("creating encrypted volume w default enc key")
		}
	}

	var resp *awsec2.Volume

	if resp, err = mustSession(ctx).CreateVolume(options); err != nil {
		return &awsec2.Volume{}, goof.WithError(
			"error creating volume", err)
	}

	// Add tags to created volume
	if err = d.createTags(ctx, *resp.VolumeId, volumeName); err != nil {
		return &awsec2.Volume{}, goof.WithError(
			"error creating tags", err)
	}

	// Wait for volume status to change
	if err = d.waitVolumeComplete(
		ctx, *resp.VolumeId, waitVolumeCreate); err != nil {
		return &awsec2.Volume{}, goof.WithError(
			"error waiting for volume creation", err)
	}

	return resp, nil
}

// Make sure Availability Zone is non-empty and valid
func (d *driver) createVolumeEnsureAvailabilityZone(
	availabilityZone *string, server *awsec2.Instance) {
	if *availabilityZone == "" {
		*availabilityZone = *server.Placement.AvailabilityZone
	}
}

// Fill in tags for volume or snapshot
func (d *driver) createTags(ctx types.Context, id, name string) (err error) {
	var (
		ctInput   *awsec2.CreateTagsInput
		inputName string
	)
	initCTInput := func() {
		if ctInput != nil {
			return
		}
		ctInput = &awsec2.CreateTagsInput{
			Resources: []*string{&id},
			Tags:      []*awsec2.Tag{},
		}
		// Append config tag to name
		inputName = d.getFullName(d.getPrintableName(name))
	}

	initCTInput()
	ctInput.Tags = append(
		ctInput.Tags,
		&awsec2.Tag{
			Key:   aws.String("Name"),
			Value: &inputName,
		})

	// TODO rexrayTag
	/*  if d.ec2Tag != "" {
	      initCTInput()
	      ctInput.Tags = append(
	        ctInput.Tags,
	        &awsec2.Tag{
	          Key:   aws.String(d.rexrayTag()),
	          Value: &d.ec2Tag,
	        })
	    }
	*/
	_, err = mustSession(ctx).CreateTags(ctInput)
	if err != nil {
		return goof.WithError("error creating tags", err)
	}
	return nil
}

var errMissingVolID = goof.New("missing volume ID")

// Wait for volume action to complete (creation, attachment, detachment)
func (d *driver) waitVolumeComplete(
	ctx types.Context, volumeID, action string) error {
	// no volume id inputted
	if volumeID == "" {
		return errMissingVolID
	}

	var (
		loop     = true
		attached = awsec2.VolumeAttachmentStateAttached
	)

	for loop {
		// update volume
		volumes, err := d.getVolume(ctx, volumeID, "")
		if err != nil {
			return goof.WithError("error getting volume", err)
		}

		// check retrieved volume
		switch action {
		case waitVolumeCreate:
			if *volumes[0].State == awsec2.VolumeStateAvailable {
				loop = false
			}
		case waitVolumeDetach:
			if len(volumes[0].Attachments) == 0 {
				loop = false
			}
		case waitVolumeAttach:
			if len(volumes[0].Attachments) == 1 &&
				*volumes[0].Attachments[0].State == attached {
				loop = false
			}
		}

		if loop {
			time.Sleep(1 * time.Second)
		}
	}

	return nil
}

// Retrieve volume or snapshot name
func (d *driver) getName(tags []*awsec2.Tag) string {
	for _, tag := range tags {
		if *tag.Key == "Name" {
			return *tag.Value
		}
	}
	return ""
}

// Retrieve current instance using EC2 API call
func (d *driver) getInstance(ctx types.Context) (awsec2.Instance, error) {
	diInput := &awsec2.DescribeInstancesInput{
		InstanceIds: []*string{mustInstanceIDID(ctx)},
	}
	resp, err := mustSession(ctx).DescribeInstances(diInput)
	if err != nil {
		return awsec2.Instance{}, goof.WithError(
			"error retrieving instance with EC2 API call", err)
	}
	return *resp.Reservations[0].Instances[0], nil
}

// Get volume or snapshot name without config tag
func (d *driver) getPrintableName(name string) string {
	return strings.TrimPrefix(name, d.tag()+ebs.TagDelimiter)
}

// Prefix volume or snapshot name with config tag
func (d *driver) getFullName(name string) string {
	if d.tag() != "" {
		return d.tag() + ebs.TagDelimiter + name
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
	return d.config.GetInt(azure.ConfigAZUREMaxRetries)
}

func (d *driver) tag() string {
	return d.config.GetString(azure.ConfigAZURETag)
}

// TODO rexrayTag
/*func (d *driver) rexrayTag() string {
  if rexrayTag := d.config.GetString("ebs.rexrayTag"); rexrayTag != "" {
    return rexrayTag
  }
  return d.config.GetString("ec2.rexrayTag")
}*/
