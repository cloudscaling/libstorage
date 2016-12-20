// +build !libstorage_storage_executor libstorage_storage_executor_azure

package executor

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

	//log "github.com/Sirupsen/logrus"

	gofig "github.com/akutz/gofig/types"
	"github.com/akutz/goof"

	"github.com/codedellemc/libstorage/api/registry"
	"github.com/codedellemc/libstorage/api/types"
	"github.com/codedellemc/libstorage/drivers/storage/azure"
	azureUtils "github.com/codedellemc/libstorage/drivers/storage/azure/utils"
)

// driver is the storage executor for the azure storage driver.
type driver struct {
	name   string
	config gofig.Config
}

func init() {
	registry.RegisterStorageExecutor(azure.Name, newDriver)
}

func newDriver() types.StorageExecutor {
	return &driver{name: azure.Name}
}

func (d *driver) Init(ctx types.Context, config gofig.Config) error {
	ctx.Info("azure_executor: Init")
	d.config = config
	return nil
}

func (d *driver) Name() string {
	return d.name
}

// Supported returns a flag indicating whether or not the platform
// implementing the executor is valid for the host on which the executor
// resides.
func (d *driver) Supported(
	ctx types.Context,
	opts types.Store) (bool, error) {
	ctx.Info("azure_executor: Supported")
	return azureUtils.IsAzureInstance(ctx)
}

// InstanceID returns the instance ID from the current instance from metadata
func (d *driver) InstanceID(
	ctx types.Context,
	opts types.Store) (*types.InstanceID, error) {
	ctx.Info("azure_executor: InstanceID")
	return azureUtils.InstanceID(ctx)
}

var errNoAvaiDevice = goof.New("no available device")

// NextDevice returns the next available device.
func (d *driver) NextDevice(
	ctx types.Context,
	opts types.Store) (string, error) {
	ctx.Info("azure_executor: NextDevice")
	// All possible device paths on Linux instances are /dev/sd[c-p]
	letters := []string{
		"c", "d", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p"}

	// Find which letters are used for local devices
	localDeviceNames := make(map[string]bool)

	localDevices, err := d.LocalDevices(
		ctx, &types.LocalDevicesOpts{Opts: opts})
	if err != nil {
		return "", goof.WithError("error getting local devices", err)
	}
	localDeviceMapping := localDevices.DeviceMap

	for localDevice := range localDeviceMapping {
		re, _ := regexp.Compile(`^/dev/` +
			azureUtils.NextDeviceInfo.Prefix +
			`(` + azureUtils.NextDeviceInfo.Pattern + `)`)
		res := re.FindStringSubmatch(localDevice)
		if len(res) > 0 {
			localDeviceNames[res[1]] = true
		}
	}

	// Find next available letter for device path
	for _, letter := range letters {
		if localDeviceNames[letter] {
			continue
		}
		return fmt.Sprintf(
			"/dev/%s%s", azureUtils.NextDeviceInfo.Prefix, letter), nil
	}
	return "", errNoAvaiDevice
}

const procPartitions = "/proc/partitions"

var devRX = regexp.MustCompile(`^sd[a-z]$`)

// Retrieve device paths currently attached and/or mounted
func (d *driver) LocalDevices(
	ctx types.Context,
	opts *types.LocalDevicesOpts) (*types.LocalDevices, error) {

	ctx.Info("azure_executor: LocalDevices")

	f, err := os.Open(procPartitions)
	if err != nil {
		return nil, goof.WithError("error reading "+procPartitions, err)
	}
	defer f.Close()

	devMap := map[string]string{}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 4 {
			continue
		}
		devName := fields[3]
		if !devRX.MatchString(devName) {
			continue
		}
		devPath := path.Join("/dev/", devName)
		devMap[devPath] = devPath
	}

	ld := &types.LocalDevices{Driver: d.Name()}
	if len(devMap) > 0 {
		ld.DeviceMap = devMap
	}

	ctx.WithField("devicemap", ld.DeviceMap).Debug("local devices")

	return ld, nil
}
