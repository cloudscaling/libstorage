// +build !libstorage_storage_driver libstorage_storage_driver_vfs

package vfs

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/Sirupsen/logrus"
	gofig "github.com/akutz/gofig/types"
	"github.com/akutz/goof"
	"github.com/akutz/gotil"
	"github.com/stretchr/testify/assert"

	"github.com/codedellemc/libstorage/api/context"
	"github.com/codedellemc/libstorage/api/server"
	apitests "github.com/codedellemc/libstorage/api/tests"
	"github.com/codedellemc/libstorage/api/types"
	"github.com/codedellemc/libstorage/api/utils"

	// load the vfs driver packages

	"github.com/codedellemc/libstorage/drivers/storage/vfs"
	_ "github.com/codedellemc/libstorage/drivers/storage/vfs/client"
	_ "github.com/codedellemc/libstorage/drivers/storage/vfs/storage"
)

func TestMain(m *testing.M) {
	server.CloseOnAbort()
	ec := m.Run()
	removeTestDirs()
	os.Exit(ec)
}

func TestClient(t *testing.T) {
	apitests.Run(t, vfs.Name, newTestConfig(t),
		func(config gofig.Config, client types.Client, t *testing.T) {
			ctx := context.Background()
			iid, err := client.Executor().InstanceID(
				ctx.WithValue(context.ServiceKey, vfs.Name),
				utils.NewStore())
			assert.NoError(t, err)
			assert.NotNil(t, iid)
		})
}

func TestRoot(t *testing.T) {
	apitests.Run(t, vfs.Name, newTestConfig(t), apitests.TestRoot)
}

var testServicesFunc = func(
	config gofig.Config, client types.Client, t *testing.T) {

	reply, err := client.API().Services(nil)
	assert.NoError(t, err)
	assert.Equal(t, len(reply), 1)

	_, ok := reply[vfs.Name]
	assert.True(t, ok)
}

func TestServices(t *testing.T) {
	apitests.Run(t, vfs.Name, newTestConfig(t), testServicesFunc)
}

func TestServicesWithControllerClient(t *testing.T) {
	apitests.RunWithClientType(
		t, types.ControllerClient, vfs.Name, newTestConfig(t), testServicesFunc)
}

func TestServiceInpspect(t *testing.T) {
	tf := func(config gofig.Config, client types.Client, t *testing.T) {

		reply, err := client.API().ServiceInspect(nil, vfs.Name)
		assert.NoError(t, err)
		assert.Equal(t, vfs.Name, reply.Name)
		assert.Equal(t, vfs.Name, reply.Driver.Name)
		assert.True(t, reply.Driver.NextDevice.Ignore)
	}
	apitests.Run(t, vfs.Name, newTestConfig(t), tf)
}

func TestExecutors(t *testing.T) {
	apitests.Run(t, vfs.Name, newTestConfig(t), apitests.TestExecutors)
}

func TestExecutorsWithControllerClient(t *testing.T) {
	apitests.RunWithClientType(
		t, types.ControllerClient, vfs.Name, newTestConfig(t),
		apitests.TestExecutorsWithControllerClient)
}

func TestExecutorHead(t *testing.T) {
	apitests.RunGroup(
		t, vfs.Name, newTestConfig(t),
		apitests.TestHeadExecutorLinux)
	//apitests.TestHeadExecutorDarwin)
	//apitests.TestHeadExecutorWindows)
}

func TestExecutorGet(t *testing.T) {
	apitests.RunGroup(
		t, vfs.Name, newTestConfig(t),
		apitests.TestGetExecutorLinux)
	//	apitests.TestGetExecutorDarwin)
	//apitests.TestGetExecutorWindows)
}

func TestStorageDriverVolumes(t *testing.T) {
	apitests.Run(t, vfs.Name, newTestConfig(t),
		func(config gofig.Config, client types.Client, t *testing.T) {

			vols, err := client.Storage().Volumes(
				context.Background().WithValue(
					context.ServiceKey, vfs.Name),
				&types.VolumesOpts{
					Attachments: types.VolAttReqTrue,
					Opts:        utils.NewStore()})
			assert.NoError(t, err)
			assert.Len(t, vols, 2)
		})
}

func TestVolumes(t *testing.T) {
	tc, _, vols, _ := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		reply, err := client.API().Volumes(nil, types.VolAttNone)
		if err != nil {
			t.Fatal(err)
		}
		for volumeID, volume := range vols {
			volume.Attachments = nil
			assert.NotNil(t, reply["vfs"][volumeID])
			assert.EqualValues(t, volume, reply["vfs"][volumeID])
		}
	}
	apitests.Run(t, vfs.Name, tc, tf)
	apitests.RunWithClientType(t, types.ControllerClient, vfs.Name, tc, tf)
}

func TestVolumesWithAttachmentsTrue(t *testing.T) {
	tc, _, vols, _ := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		reply, err := client.API().Volumes(nil, types.VolAttReqTrue)
		if err != nil {
			t.Fatal(err)
		}

		assert.NotNil(t, reply["vfs"]["vfs-000"])
		assert.NotNil(t, reply["vfs"]["vfs-001"])
		assert.Nil(t, reply["vfs"]["vfs-002"])
		assert.EqualValues(t, vols["vfs-000"], reply["vfs"]["vfs-000"])
		assert.EqualValues(t, vols["vfs-001"], reply["vfs"]["vfs-001"])
	}
	apitests.Run(t, vfs.Name, tc, tf)
}

func TestVolumesWithAttachmentsRequested(t *testing.T) {
	tc, _, vols, _ := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		reply, err := client.API().Volumes(nil, types.VolAttReq)
		if err != nil {
			t.Fatal(err)
		}

		assert.NotNil(t, reply["vfs"]["vfs-000"])
		assert.NotNil(t, reply["vfs"]["vfs-001"])
		assert.NotNil(t, reply["vfs"]["vfs-002"])
		assert.EqualValues(t, vols["vfs-000"], reply["vfs"]["vfs-000"])
		assert.EqualValues(t, vols["vfs-001"], reply["vfs"]["vfs-001"])
		assert.Len(t, reply["vfs"]["vfs-002"].Attachments, 0)
	}
	apitests.Run(t, vfs.Name, tc, tf)
}

func TestVolumesWithAttachmentsNone(t *testing.T) {
	tc, _, _, _ := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		reply, err := client.API().Volumes(nil, types.VolAttNone)
		if err != nil {
			t.Fatal(err)
		}

		assert.NotNil(t, reply["vfs"]["vfs-000"])
		assert.NotNil(t, reply["vfs"]["vfs-001"])
		assert.NotNil(t, reply["vfs"]["vfs-002"])
		assert.Len(t, reply["vfs"]["vfs-000"].Attachments, 0)
		assert.Len(t, reply["vfs"]["vfs-001"].Attachments, 0)
		assert.Len(t, reply["vfs"]["vfs-002"].Attachments, 0)
	}
	apitests.Run(t, vfs.Name, tc, tf)
}

func TestVolumesWithAttachmentsAttached(t *testing.T) {
	tc, _, vols, _ := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		reply, err := client.API().Volumes(nil, types.VolAttReqOnlyAttachedVols)
		if err != nil {
			t.Fatal(err)
		}

		assert.NotNil(t, reply["vfs"]["vfs-000"])
		assert.NotNil(t, reply["vfs"]["vfs-001"])
		assert.Nil(t, reply["vfs"]["vfs-002"])
		assert.EqualValues(t, vols["vfs-000"], reply["vfs"]["vfs-000"])
		assert.EqualValues(t, vols["vfs-001"], reply["vfs"]["vfs-001"])
	}
	apitests.Run(t, vfs.Name, tc, tf)
}

func TestVolumesWithAttachmentsUnattached(t *testing.T) {
	tc, _, _, _ := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		reply, err := client.API().Volumes(nil,
			types.VolAttReqOnlyUnattachedVols)
		if err != nil {
			t.Fatal(err)
		}

		assert.Nil(t, reply["vfs"]["vfs-000"])
		assert.Nil(t, reply["vfs"]["vfs-001"])
		assert.NotNil(t, reply["vfs"]["vfs-002"])
		assert.Len(t, reply["vfs"]["vfs-002"].Attachments, 0)
	}
	apitests.Run(t, vfs.Name, tc, tf)
}

func TestVolumesWithAttachmentsAttachedAndUnattached(t *testing.T) {
	tc, _, vols, _ := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		reply, err := client.API().Volumes(nil,
			types.VolAttReqOnlyAttachedVols|types.VolAttReqOnlyUnattachedVols)
		if err != nil {
			t.Fatal(err)
		}

		assert.NotNil(t, reply["vfs"]["vfs-000"])
		assert.NotNil(t, reply["vfs"]["vfs-001"])
		assert.NotNil(t, reply["vfs"]["vfs-002"])
		assert.EqualValues(t, vols["vfs-000"], reply["vfs"]["vfs-000"])
		assert.EqualValues(t, vols["vfs-001"], reply["vfs"]["vfs-001"])
	}
	apitests.Run(t, vfs.Name, tc, tf)
}

func TestVolumesWithAttachmentsAttachedToMeAndAvailable(t *testing.T) {
	tc, _, vols, _ := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		reply, err := client.API().Volumes(nil,
			types.VolAttReqOnlyVolsAttachedToInstanceOrUnattachedVols)
		if err != nil {
			t.Fatal(err)
		}

		assert.NotNil(t, reply["vfs"]["vfs-000"])
		assert.NotNil(t, reply["vfs"]["vfs-001"])
		assert.NotNil(t, reply["vfs"]["vfs-002"])
		assert.EqualValues(t, vols["vfs-000"], reply["vfs"]["vfs-000"])
		assert.EqualValues(t, vols["vfs-001"], reply["vfs"]["vfs-001"])
		assert.Equal(
			t, types.VolumeAttached, reply["vfs"]["vfs-000"].AttachmentState)
		assert.Equal(
			t, types.VolumeAttached, reply["vfs"]["vfs-001"].AttachmentState)
		assert.Equal(
			t, types.VolumeAvailable, reply["vfs"]["vfs-002"].AttachmentState)
	}
	apitests.Run(t, vfs.Name, tc, tf)
}

func TestVolumesWithAttachmentsMineWithNotMyInstanceID(
	t *testing.T) {
	tc, _, _, _ := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {

		ctx := context.Background()
		iidm := types.InstanceIDMap{
			"vfs": &types.InstanceID{ID: "none", Driver: "vfs"},
		}
		ctx = ctx.WithValue(context.AllInstanceIDsKey, iidm)

		reply, err := client.API().Volumes(ctx, types.VolAttReqForInstance)
		if err != nil {
			t.Fatal(err)
		}

		assert.NotNil(t, reply["vfs"]["vfs-000"])
		assert.NotNil(t, reply["vfs"]["vfs-001"])
		assert.NotNil(t, reply["vfs"]["vfs-002"])
		assert.Len(t, reply["vfs"]["vfs-000"].Attachments, 0)
		assert.Len(t, reply["vfs"]["vfs-001"].Attachments, 0)
		assert.Len(t, reply["vfs"]["vfs-002"].Attachments, 0)
	}
	apitests.RunWithClientType(t, types.ControllerClient, vfs.Name, tc, tf)
}

func TestVolumesWithAttachmentsAttachedAndMineWithNotMyInstanceID(
	t *testing.T) {
	tc, _, _, _ := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {

		ctx := context.Background()
		iidm := types.InstanceIDMap{
			"vfs": &types.InstanceID{ID: "none", Driver: "vfs"},
		}
		ctx = ctx.WithValue(context.AllInstanceIDsKey, iidm)

		reply, err := client.API().Volumes(ctx,
			types.VolAttReqOnlyVolsAttachedToInstance)
		if err != nil {
			t.Fatal(err)
		}

		assert.Nil(t, reply["vfs"]["vfs-000"])
		assert.Nil(t, reply["vfs"]["vfs-001"])
		assert.Nil(t, reply["vfs"]["vfs-002"])
	}
	apitests.RunWithClientType(t, types.ControllerClient, vfs.Name, tc, tf)
}

func TestVolumesWithAttachmentsWithControllerClient(t *testing.T) {
	tc, _, _, _ := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {

		_, err := client.API().Volumes(nil, types.VolAttReqTrue)
		assert.Error(t, err)
		assert.Equal(t, "batch processing error", err.Error())
	}

	apitests.RunWithClientType(t, types.ControllerClient, vfs.Name, tc, tf)
}

func TestVolumesByService(t *testing.T) {
	tc, _, vols, _ := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		reply, err := client.API().VolumesByService(nil, "vfs", 0)
		if err != nil {
			t.Fatal(err)
		}
		for volumeID, volume := range vols {
			volume.Attachments = nil
			assert.NotNil(t, reply[volumeID])
			assert.EqualValues(t, volume, reply[volumeID])
		}
	}
	apitests.Run(t, vfs.Name, tc, tf)
}

func TestVolumesByServiceWithAttachments(t *testing.T) {
	tc, _, vols, _ := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		reply, err := client.API().VolumesByService(
			nil, "vfs", types.VolAttReqTrue)
		if err != nil {
			t.Fatal(err)
		}
		assert.NotNil(t, reply["vfs-000"])
		assert.NotNil(t, reply["vfs-001"])
		assert.Nil(t, reply["vfs-002"])
		assert.EqualValues(t, vols["vfs-000"], reply["vfs-000"])
		assert.EqualValues(t, vols["vfs-001"], reply["vfs-001"])
	}
	apitests.Run(t, vfs.Name, tc, tf)
}

func TestVolumeInspect(t *testing.T) {
	tc, _, vols, _ := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		reply, err := client.API().VolumeInspect(nil, "vfs", "vfs-000", 0)
		if err != nil {
			t.Fatal(err)
		}
		vols[reply.ID].Attachments = nil
		assert.NotNil(t, reply)
		assert.EqualValues(t, vols[reply.ID], reply)
	}
	apitests.Run(t, vfs.Name, tc, tf)
}

func TestVolumeInspectWithAttachments(t *testing.T) {
	tc, _, vols, _ := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		reply, err := client.API().VolumeInspect(
			nil, "vfs", "vfs-000", types.VolAttReqTrue)
		if err != nil {
			t.Fatal(err)
		}
		assert.NotNil(t, reply)
		assert.EqualValues(t, vols[reply.ID], reply)
	}
	apitests.Run(t, vfs.Name, tc, tf)
}

func TestSnapshots(t *testing.T) {
	tc, _, _, snaps := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		reply, err := client.API().Snapshots(nil)
		if err != nil {
			t.Fatal(err)
		}
		for snapshotID, snapshot := range snaps {
			assert.NotNil(t, reply["vfs"][snapshotID])
			assert.EqualValues(t, snapshot, reply["vfs"][snapshotID])
		}
	}
	apitests.Run(t, vfs.Name, tc, tf)
}

func TestSnapshotsByService(t *testing.T) {
	tc, _, _, snaps := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		reply, err := client.API().SnapshotsByService(nil, "vfs")
		if err != nil {
			t.Fatal(err)
		}
		for snapshotID, snapshot := range snaps {
			assert.NotNil(t, reply[snapshotID])
			assert.EqualValues(t, snapshot, reply[snapshotID])
		}
	}
	apitests.Run(t, vfs.Name, tc, tf)
}

func TestVolumeCreate(t *testing.T) {
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		volumeName := "Volume 003"
		availabilityZone := "US"
		iops := int64(1000)
		size := int64(10240)
		volType := "myType"

		opts := map[string]interface{}{
			"priority": 2,
			"owner":    "root@example.com",
		}

		request := &types.VolumeCreateRequest{
			Name:             volumeName,
			AvailabilityZone: &availabilityZone,
			IOPS:             &iops,
			Size:             &size,
			Type:             &volType,
			Opts:             opts,
		}

		reply, err := client.API().VolumeCreate(nil, vfs.Name, request)
		assert.NoError(t, err)
		if err != nil {
			t.FailNow()
		}
		assert.NotNil(t, reply)

		assertVolDir(t, config, reply.ID, true)
		assert.Equal(t, availabilityZone, reply.AvailabilityZone)
		assert.Equal(t, iops, reply.IOPS)
		assert.Equal(t, volumeName, reply.Name)
		assert.Equal(t, size, reply.Size)
		assert.Equal(t, volType, reply.Type)
		assert.Equal(t, "2", reply.Fields["priority"])
		assert.Equal(t, "root@example.com", reply.Fields["owner"])
	}

	apitests.Run(t, vfs.Name, newTestConfig(t), tf)
}

func TestVolumeCopy(t *testing.T) {
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		request := &types.VolumeCopyRequest{
			VolumeName: "Copy of Volume 000",
			Opts: map[string]interface{}{
				"priority": 7,
				"owner":    "user@example.com",
			},
		}

		reply, err := client.API().VolumeCopy(nil, vfs.Name, "vfs-000", request)
		assert.NoError(t, err)
		if err != nil {
			t.FailNow()
		}

		assert.NotNil(t, reply)

		assertVolDir(t, config, reply.ID, true)
		assert.Equal(t, "vfs-003", reply.ID)
		assert.Equal(t, request.VolumeName, reply.Name)
		assert.Equal(t, "7", reply.Fields["priority"])
		assert.Equal(t, request.Opts["owner"], reply.Fields["owner"])
	}

	apitests.Run(t, vfs.Name, newTestConfig(t), tf)
}

func TestVolumeRemove(t *testing.T) {

	tf1 := func(config gofig.Config, client types.Client, t *testing.T) {
		assertVolDir(t, config, "vfs-002", true)
		err := client.API().VolumeRemove(nil, vfs.Name, "vfs-002")
		assert.NoError(t, err)
		assertVolDir(t, config, "vfs-002", false)
	}

	apitests.Run(t, vfs.Name, newTestConfig(t), tf1)

	tf2 := func(config gofig.Config, client types.Client, t *testing.T) {
		err := client.API().VolumeRemove(nil, vfs.Name, "vfs-002")
		assert.Error(t, err)
		httpErr := err.(goof.HTTPError)
		assert.Equal(t, "resource not found", httpErr.Error())
		assert.Equal(t, 404, httpErr.Status())
	}

	apitests.RunGroup(t, vfs.Name, newTestConfig(t), tf1, tf2)
}

func TestVolumeSnapshot(t *testing.T) {
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		volumeID := "vfs-000"
		snapshotName := "snapshot1"
		opts := map[string]interface{}{
			"priority": 2,
		}

		request := &types.VolumeSnapshotRequest{
			SnapshotName: snapshotName,
			Opts:         opts,
		}

		reply, err := client.API().VolumeSnapshot(
			nil, vfs.Name, volumeID, request)
		assert.NoError(t, err)
		if err != nil {
			t.FailNow()
		}
		assert.Equal(t, snapshotName, reply.Name)
		assert.Equal(t, volumeID, reply.VolumeID)

		snap, err := client.API().SnapshotInspect(nil, vfs.Name, reply.ID)
		assert.NoError(t, err)
		if err != nil {
			t.FailNow()
		}
		assert.Equal(t, snapshotName, snap.Name)
		assert.Equal(t, volumeID, snap.VolumeID)

		snapCountEqual := false
		for x := 0; x < 10; x++ {
			time.Sleep(time.Duration(1) * time.Second)
			snapshots, err := client.API().SnapshotsByService(nil, vfs.Name)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			if len(snapshots) != 10 {
				continue
			}
			snapCountEqual = assert.EqualValues(t, 10, len(snapshots))
			break
		}
		assert.True(t, snapCountEqual)
	}
	apitests.Run(t, vfs.Name, newTestConfig(t), tf)
}

func TestVolumeCreateFromSnapshot(t *testing.T) {
	tf := func(config gofig.Config, client types.Client, t *testing.T) {

		ogVol, err := client.API().VolumeInspect(
			nil, "vfs", "vfs-000", types.VolAttReqTrue)
		assert.NoError(t, err)

		volumeName := "Volume 003"
		size := int64(40960)

		request := &types.VolumeCreateRequest{
			Name: volumeName,
			Size: &size,
			Opts: map[string]interface{}{
				"priority": 4,
				"owner":    "user@example.com",
			},
		}

		reply, err := client.API().VolumeCreateFromSnapshot(
			nil, vfs.Name, "vfs-000-002", request)
		assert.NoError(t, err)
		if err != nil {
			t.FailNow()
		}

		assert.NotNil(t, reply)

		assertVolDir(t, config, reply.ID, true)
		assert.Equal(t, ogVol.AvailabilityZone, reply.AvailabilityZone)
		assert.Equal(t, ogVol.IOPS, reply.IOPS)
		assert.Equal(t, volumeName, reply.Name)
		assert.Equal(t, size, reply.Size)
		assert.Equal(t, ogVol.Type, reply.Type)
		assert.Equal(t, "4", reply.Fields["priority"])
		assert.Equal(t, request.Opts["owner"], reply.Fields["owner"])

	}
	apitests.Run(t, vfs.Name, newTestConfig(t), tf)
}

func TestVolumeAttach(t *testing.T) {
	tf := func(config gofig.Config, client types.Client, t *testing.T) {

		nextDevice, err := client.Executor().NextDevice(
			context.Background().WithValue(context.ServiceKey, vfs.Name),
			utils.NewStore())
		assert.NoError(t, err)
		if err != nil {
			t.FailNow()
		}

		request := &types.VolumeAttachRequest{
			NextDeviceName: &nextDevice,
		}

		reply, attTokn, err := client.API().VolumeAttach(
			nil, vfs.Name, "vfs-002", request)
		assert.NoError(t, err)
		if reply == nil {
			t.FailNow()
		}
		assert.Equal(t, "/dev/xvdc", attTokn)
		assert.Equal(t, "vfs-002", reply.ID)
		assert.Equal(t, "/dev/xvdc", reply.Attachments[0].DeviceName)

	}
	apitests.Run(t, vfs.Name, newTestConfig(t), tf)
}

func TestVolumeAttachWithControllerClient(t *testing.T) {
	tf := func(config gofig.Config, client types.Client, t *testing.T) {

		_, err := client.Executor().NextDevice(
			context.Background().WithValue(context.ServiceKey, vfs.Name),
			utils.NewStore())
		assert.Error(t, err)
		assert.Equal(t, "unsupported op for client type", err.Error())

		_, _, err = client.API().VolumeAttach(
			nil, vfs.Name, "vfs-002", &types.VolumeAttachRequest{})
		assert.Error(t, err)
		assert.Equal(t, "unsupported op for client type", err.Error())
	}

	apitests.RunWithClientType(
		t, types.ControllerClient, vfs.Name, newTestConfig(t), tf)
}

func TestVolumeDetach(t *testing.T) {
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		request := &types.VolumeDetachRequest{}
		reply, err := client.API().VolumeDetach(
			nil, vfs.Name, "vfs-001", request)
		assert.NoError(t, err)
		assert.Equal(t, "vfs-001", reply.ID)
		assert.Equal(t, 0, len(reply.Attachments))

		reply, err = client.API().VolumeInspect(
			nil, vfs.Name, "vfs-001", 0)
		assert.NoError(t, err)
		assert.Equal(t, "vfs-001", reply.ID)
		assert.Equal(t, 0, len(reply.Attachments))
	}
	apitests.Run(t, vfs.Name, newTestConfig(t), tf)
}

func TestVolumeDetachWithControllerClient(t *testing.T) {
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		_, err := client.API().VolumeDetach(
			nil, vfs.Name, "vfs-001", &types.VolumeDetachRequest{})
		assert.Error(t, err)
		assert.Equal(t, "unsupported op for client type", err.Error())
	}
	apitests.RunWithClientType(
		t, types.ControllerClient, vfs.Name, newTestConfig(t), tf)
}

func TestVolumeDetachAllForService(t *testing.T) {
	tc, _, vols, _ := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		request := &types.VolumeDetachRequest{}
		reply, err := client.API().VolumeDetachAllForService(
			nil, vfs.Name, request)
		assert.NoError(t, err)
		for _, v := range vols {
			v.Attachments = nil
		}
		assert.Equal(t, 3, len(reply))
		assert.EqualValues(t, vols, reply)

		reply, err = client.API().VolumesByService(
			nil, vfs.Name, types.VolAttReqTrue)
		assert.NoError(t, err)
		assert.Equal(t, 0, len(reply))

		reply, err = client.API().VolumesByService(
			nil, vfs.Name, 0)
		assert.NoError(t, err)
		assert.Equal(t, 3, len(reply))
		assert.EqualValues(t, vols, reply)
	}
	apitests.Run(t, vfs.Name, tc, tf)
}

func TestVolumeDetachAllForServiceWithControllerClient(t *testing.T) {
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		_, err := client.API().VolumeDetachAllForService(
			nil, vfs.Name, &types.VolumeDetachRequest{})
		assert.Error(t, err)
		assert.Equal(t, "unsupported op for client type", err.Error())
	}
	apitests.RunWithClientType(
		t, types.ControllerClient, vfs.Name, newTestConfig(t), tf)
}

func TestVolumeDetachAll(t *testing.T) {
	tc, _, vols, _ := newTestConfigAll(t)
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		request := &types.VolumeDetachRequest{}
		reply, err := client.API().VolumeDetachAll(
			nil, request)
		assert.NoError(t, err)
		for _, v := range vols {
			v.Attachments = nil
		}
		assert.Equal(t, 1, len(reply))
		assert.Equal(t, 3, len(reply[vfs.Name]))
		assert.EqualValues(t, vols, reply[vfs.Name])

		reply, err = client.API().Volumes(nil, types.VolAttReqTrue)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(reply))
		assert.Equal(t, 0, len(reply[vfs.Name]))

		reply, err = client.API().Volumes(nil, 0)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(reply))
		assert.Equal(t, 3, len(reply[vfs.Name]))
	}
	apitests.Run(t, vfs.Name, tc, tf)
}

func TestVolumeDetachAllWithControllerClient(t *testing.T) {
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		_, err := client.API().VolumeDetachAll(
			nil, &types.VolumeDetachRequest{})
		assert.Error(t, err)
		assert.Equal(t, "unsupported op for client type", err.Error())
	}
	apitests.RunWithClientType(
		t, types.ControllerClient, vfs.Name, newTestConfig(t), tf)
}

func TestSnapshotCopy(t *testing.T) {
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		snapshotName := "Snapshot from vfs-000-000"

		opts := map[string]interface{}{
			"priority": 2,
			"owner":    "root@example.com",
		}

		request := &types.SnapshotCopyRequest{
			SnapshotName: snapshotName,
			Opts:         opts,
		}

		reply, err := client.API().SnapshotCopy(
			nil, vfs.Name, "vfs-000-000", request)
		assert.NoError(t, err)
		apitests.LogAsJSON(reply, t)

		assert.Equal(t, snapshotName, reply.Name)
		assert.Equal(t, "vfs-000", reply.VolumeID)
		assert.Equal(t, "2", reply.Fields["priority"])
		assert.Equal(t, "root@example.com", reply.Fields["owner"])

	}
	apitests.Run(t, vfs.Name, newTestConfig(t), tf)
}

func TestSnapshotRemove(t *testing.T) {
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		reply, err := client.API().SnapshotInspect(nil, "vfs", "vfs-000-002")
		assert.NoError(t, err)
		assert.NotNil(t, reply)
		assert.Equal(t, "vfs-000-002", reply.ID)

		err = client.API().SnapshotRemove(nil, "vfs", reply.ID)
		assert.NoError(t, err)

		reply, err = client.API().SnapshotInspect(nil, "vfs", "vfs-000-002")
		assert.Error(t, err)
		assert.Nil(t, reply)

	}
	apitests.Run(t, vfs.Name, newTestConfig(t), tf)
}

func TestInstanceID(t *testing.T) {
	iid, err := instanceID()
	assert.NoError(t, err)
	if err != nil {
		t.FailNow()
	}
	apitests.Run(
		t, vfs.Name, newTestConfig(t),
		(&apitests.InstanceIDTest{
			Driver:   vfs.Name,
			Expected: iid,
		}).Test)
}

func TestInstance(t *testing.T) {
	iid, err := instanceID()
	assert.NoError(t, err)
	if err != nil {
		t.FailNow()
	}
	apitests.Run(
		t, vfs.Name, nil,
		(&apitests.InstanceTest{
			Driver: vfs.Name,
			Expected: &types.Instance{
				InstanceID: iid,
				Name:       "vfsInstance",
			},
		}).Test)
}

func TestNextDevice(t *testing.T) {
	apitests.RunGroup(
		t, vfs.Name, newTestConfig(t),
		(&apitests.NextDeviceTest{
			Driver:   vfs.Name,
			Expected: "/dev/xvdc",
		}).Test)
}

func TestLocalDevices(t *testing.T) {
	cfg, dfc, _, _ := newTestConfigAll(t)
	scn := bufio.NewScanner(bytes.NewBuffer(dfc))
	dfcMap := map[string]string{}
	for scn.Scan() {
		p := strings.SplitN(scn.Text(), "=", 2)
		k := p[0]
		v := ""
		if len(p) > 1 {
			v = p[1]
		}
		if len(v) > 0 {
			dfcMap[k] = v
		}
	}

	apitests.RunGroup(
		t, vfs.Name, cfg,
		(&apitests.LocalDevicesTest{
			Driver:   vfs.Name,
			Expected: &types.LocalDevices{Driver: vfs.Name, DeviceMap: dfcMap},
		}).Test)
}

func removeTestDirs() {
	testDirsLock.RLock()
	defer testDirsLock.RUnlock()
	for _, d := range testDirs {
		os.RemoveAll(d)
		log.WithField("path", d).Debug("removed test dir")
	}
}

func instanceID() (*types.InstanceID, error) {
	hostName, err := utils.HostName()
	if err != nil {
		return nil, err
	}
	iid := &types.InstanceID{ID: hostName, Driver: vfs.Name}
	if ok, _ := strconv.ParseBool(os.Getenv("VFS_INSTANCEID_USE_FIELDS")); ok {
		iid.Fields = map[string]string{"region": "east"}
	}
	return iid, nil
}

func assertVolDir(
	t *testing.T, config gofig.Config, volumeID string, exists bool) {
	volDir := path.Join(vfs.VolumesDirPath(config), volumeID)
	assert.Equal(t, exists, gotil.FileExists(volDir))
}

func assertSnapDir(
	t *testing.T, config gofig.Config, snapshotID string, exists bool) {
	snapDir := path.Join(vfs.SnapshotsDirPath(config), snapshotID)
	assert.Equal(t, exists, gotil.FileExists(snapDir))
}

var (
	testDirs     []string
	testDirsLock = &sync.RWMutex{}
)

func newTestConfig(t *testing.T) []byte {
	tc, _, _, _ := newTestConfigAll(t)
	return tc
}

func newTestConfigAll(
	t *testing.T) (
	[]byte,
	[]byte,
	map[string]*types.Volume,
	map[string]*types.Snapshot) {

	hostName, err := utils.HostName()
	assert.NoError(t, err)
	if err != nil {
		t.FailNow()
	}

	d, err := ioutil.TempDir("", "")
	assert.NoError(t, err)
	if err != nil {
		t.FailNow()
	}
	t.Logf("created temp vfs root dir: %s", d)

	func() {
		testDirsLock.Lock()
		defer testDirsLock.Unlock()
		testDirs = append(testDirs, d)
	}()

	vd := path.Join(d, "vol")
	if err := os.MkdirAll(vd, 0755); err != nil {
		assert.NoError(t, err)
		t.FailNow()
	}
	t.Logf("created temp vfs vol dir: %s", vd)
	sd := path.Join(d, "snap")
	if err := os.MkdirAll(sd, 0755); err != nil {
		assert.NoError(t, err)
		t.FailNow()
	}
	t.Logf("created temp vfs snap dir: %s", sd)

	dp := path.Join(d, "dev")
	devFileContents := []byte(fmt.Sprintf(devFile, d))
	err = ioutil.WriteFile(dp, devFileContents, 0644)
	assert.NoError(t, err)
	if err != nil {
		t.FailNow()
	}
	t.Logf("created temp vfs dev file: %s", dp)

	vols := map[string]*types.Volume{}
	snaps := map[string]*types.Snapshot{}

	for x := 0; x < 3; x++ {
		var vj []byte
		if x < 2 {
			vj = []byte(fmt.Sprintf(volJSON, x, hostName))
		} else {
			vj = []byte(fmt.Sprintf(volNoAttachJSON, x, hostName))
		}
		v := &types.Volume{}
		if err := json.Unmarshal(vj, v); err != nil {
			assert.NoError(t, err)
			t.FailNow()
		}
		vols[v.ID] = v
		vjp := path.Join(vd, fmt.Sprintf("%s.json", v.ID))
		os.MkdirAll(path.Join(vd, v.ID), 0755)
		if err := ioutil.WriteFile(vjp, vj, 0644); err != nil {
			assert.NoError(t, err)
			t.FailNow()
		}

		for y := 0; y < 3; y++ {
			sj := []byte(fmt.Sprintf(snapJSON, x, y, time.Now().Unix()))
			s := &types.Snapshot{}
			if err := json.Unmarshal(sj, s); err != nil {
				assert.NoError(t, err)
				t.FailNow()
			}
			snaps[s.ID] = s
			sjp := path.Join(sd, fmt.Sprintf("vfs-%03d-%03d.json", x, y))
			if err := ioutil.WriteFile(sjp, sj, 0644); err != nil {
				assert.NoError(t, err)
				t.FailNow()
			}
		}
	}

	return []byte(fmt.Sprintf(configYAML, d)), devFileContents, vols, snaps
}

const configYAML = "vfs:\n  root: %s"

const volJSON = `{
    "availabilityZone": "US",
    "iops":             1000,
    "name":             "Volume %03[1]d",
    "size":             10240,
    "id":               "vfs-%03[1]d",
    "type":             "myType",
    "attachments": [{
        "volumeID":     "%03[1]d",
        "instanceID":   {
            "id":       "%[2]s"
        },
        "status":       "attached"
    }],
    "attachmentState":  2,
    "fields": {
        "owner":        "root@example.com",
        "priority":     "2"
    }
}`

const volNoAttachJSON = `{
    "availabilityZone": "US",
    "iops":             1000,
    "name":             "Volume %03[1]d",
    "size":             10240,
    "id":               "vfs-%03[1]d",
    "type":             "myType",
    "attachmentState":  3,
    "fields": {
        "owner":        "root@example.com",
        "priority":     "2"
    }
}`

const snapJSON = `{
    "name":             "Snapshot %03[1]d-%03[2]d",
    "id":               "vfs-%03[1]d-%03[2]d",
    "volumeID":         "vfs-%03[1]d",
    "volumeSize":       10240,
    "status":           "online",
    "startTime":        %[3]d,
    "fields": {
        "owner":        "root@example.com",
        "priority":     "2"
    }
}`

const devFile = `/dev/xvda=%[1]s/vfs-000
/dev/xvdb=%[1]s/vfs-001
/dev/xvdc
/dev/xvdd
/dev/xvde
/dev/xvdf`
