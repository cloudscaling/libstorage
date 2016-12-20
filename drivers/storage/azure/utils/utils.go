// +build !libstorage_storage_driver libstorage_storage_driver_azure

package utils

import (
  "encoding/json"
  "fmt"
  "io/ioutil"
  "net"
  "net/http"
  "time"

  "github.com/codedellemc/libstorage/api/types"
  "github.com/codedellemc/libstorage/drivers/storage/azure"
)


// IsAzureInstance returns a flag indicating whether the executing host is an Azure
// instance based on whether or not the metadata URL can be accessed.
func IsAzureInstance(ctx types.Context) (bool, error) {
  // TODO: impl for Azure, e.g. as described in 
  // http://blog.mszcool.com/index.php/2015/04/detecting-if-a-virtual-machine-runs-in-microsoft-azure-linux-windows-to-protect-your-software-when-distributed-via-the-azure-marketplace/
  return true, nil
}

// InstanceID returns the instance ID for the local host.
func InstanceID(ctx types.Context) (*types.InstanceID, error) {
  // TODO: read from bios as described in 
  // https://azure.microsoft.com/en-us/blog/accessing-and-using-azure-vm-unique-id/
  return nil, err
}
