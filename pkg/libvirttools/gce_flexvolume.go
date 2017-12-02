/*
Copyright 2017 Mirantis

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package libvirttools

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"gopkg.in/freddierice/go-losetup.v1"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	
	libvirtxml "github.com/libvirt/libvirt-go-xml"

	"github.com/Mirantis/virtlet/pkg/utils"
	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
	"github.com/golang/glog"
)

type gceVolumeOptions struct {
	Name string `json:"name"`
	Zone string `json:"zone"`
	Project string `json:"project"`
	
}

func (vo *gceVolumeOptions) validate() error {
	return nil
}

// gceDeviceVolume denotes a gce device that's made accessible for a VM
type gceDeviceVolume struct {
	volumeBase
	opts		*gceVolumeOptions
	client          *compute.Service
	instanceName	string
	loopDevice	*losetup.Device
	debugFile	*os.File
}
type BlockDevice struct {
	InstanceName	string
	VolumeID	string
	DeviceName	string
	Zone		string
	Status		string
	NetworkName	string
}

func (d *gceDeviceVolume) GetVolumeMapping() ([]*BlockDevice, error) {
	glog.V(2).Info("Calling GetVolumeMapping");
	
	diskMap := make(map[string]*compute.Disk)
	disks, err := d.client.Disks.List(d.opts.Project, d.opts.Zone).Do()
	if err != nil {
		return []*BlockDevice{}, err
	}
	for _, disk := range disks.Items {
		diskMap[disk.SelfLink] = disk
	}

	instances, err := d.client.Instances.List(d.opts.Project, d.opts.Zone).Do()
	if err != nil {
		return []*BlockDevice{}, err
	}
	var ret []*BlockDevice
	for _, instance := range instances.Items {
		for _, disk := range instance.Disks {
			ret = append(ret, &BlockDevice{
				InstanceName:   instance.Name,
				VolumeID:     diskMap[disk.Source].Name,
				DeviceName:   fmt.Sprintf("/dev/disk/by-id/google-%s", disk.DeviceName),
				Zone:	      diskMap[disk.Source].Zone,
				Status:       diskMap[disk.Source].Status,
				NetworkName:  disk.Source,
			})

		}
	}
	return ret, nil
}

func getLocalDevices() (deviceNames []string, err error) {
	file := "/proc/partitions"
	contentBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return []string{}, err
	}

	content := string(contentBytes)

	lines := strings.Split(content, "\n")
	for _, line := range lines[2:] {
		fields := strings.Fields(line)
		if len(fields) == 4 {
			deviceNames = append(deviceNames, fields[3])
		}
	}

	return deviceNames, nil
}

func (d *gceDeviceVolume) GetDeviceNextAvailable() (string, error) {
	letters := []string{
		"a", "b", "c", "d", "e", "f", "g", "h",
		"i", "j", "k", "l", "m", "n", "o", "p"}

	blockDeviceNames := make(map[string]bool)

	blockDeviceMapping, err := d.GetVolumeMapping()
	if err != nil {
		return "", err
	}

	for _, blockDevice := range blockDeviceMapping {
		re, _ := regexp.Compile(`^/dev/sd([a-z])`)
		res := re.FindStringSubmatch(blockDevice.DeviceName)
		if len(res) > 0 {
			blockDeviceNames[res[1]] = true
		}
	}

	localDevices, err := getLocalDevices()
	if err != nil {
		return "", err
	}

	for _, localDevice := range localDevices {
		re, _ := regexp.Compile(`^sd([a-z])`)
		res := re.FindStringSubmatch(localDevice)
		if len(res) > 0 {
			blockDeviceNames[res[1]] = true
		}
	}

	for _, letter := range letters {
		if !blockDeviceNames[letter] {
			nextDeviceName := "/dev/sd" + letter
			glog.V(2).Infof("Got next device name: %q" , nextDeviceName)
			return nextDeviceName, nil
		}
	}
	return "", errors.New("No available device")
}

func getCurrentInstanceName() (string, error) {
	conn, err := net.DialTimeout("tcp", "metadata.google.internal:80", 50 * time.Millisecond)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	url := "http://metadata.google.internal/computeMetadata/v1/instance/name"
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Error: %v\n", err)
	}

	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	s := buf.String()
	return s, nil
}

func newGCEDeviceVolume(volumeName, configPath string, config *VMConfig, owner VolumeOwner) (VMVolume, error) {
	var opts gceVolumeOptions
	if err := utils.ReadJson(configPath, &opts); err != nil {
		return nil, fmt.Errorf("failed to parse gce volume config %q: %v", configPath, err)
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}
	client, err := google.DefaultClient(context.Background(), compute.ComputeScope)
	if err !=nil {
		return nil, err
	}
	computeService, err := compute.New(client)
	if err != nil {
		return nil, err
	}
	instanceName, err := getCurrentInstanceName()
	if err != nil {
		return nil, err
	}
	// This is for debugging purposes only.
	// The problem is that kubelet grabs CombinedOutput() from the process
	// and tries to parse it as JSON (need to recheck this,
	// maybe submit a PS to fix it)
	f, err := os.OpenFile("/tmp/flexvolume-gce.log", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0666)
	return &gceDeviceVolume {
		volumeBase: volumeBase{config, owner},
		opts:       &opts,
		client:	    computeService,
		instanceName: instanceName,
		debugFile: f,
	}, nil
}



func (v *gceDeviceVolume) Uuid() string {
	return v.opts.Name
}

func (v *gceDeviceVolume) Setup(volumeMap map[string]string) (*libvirtxml.DomainDisk, error) {
	fmt.Fprintf(v.debugFile,"Setup of GCE volume :%+v\n",v);
	query := v.client.Disks.List(v.opts.Project, v.opts.Zone)
	query.Filter(fmt.Sprintf("name eq %s", v.opts.Name))
	disks, err := query.Do()
	if err != nil {
		fmt.Fprintf(v.debugFile,"Error while querying :%v\n",err);
		return nil, err
	}
	if len(disks.Items) != 1 {
		fmt.Fprintf(v.debugFile,"Invalid number of found disks :%v\n",disks);
		return nil, errors.New("No available device")
	}

	disk := &compute.AttachedDisk{
		AutoDelete: false,
		Boot:       false,
		Source:     disks.Items[0].SelfLink,
	}
	fmt.Fprintf(v.debugFile,"Will ask GCE to attach Disk\n");
	glog.V(2).Info("About to start attaching device on host");
	operation, err := v.client.Instances.AttachDisk(
		v.opts.Project,
		v.opts.Zone,
		v.instanceName,
		disk).Do()
	fmt.Fprintf(v.debugFile,"%#v\n", operation)
	if err != nil {
		fmt.Fprintf(v.debugFile,"Unable to attach disk:%v\n",err);
		return nil, err
	}
	err2 := v.waitUntilOperationIsFinished(operation)
	if err2 != nil {
		fmt.Fprintf(v.debugFile,"Unable to wait for disk attach:%v\n",err2);
		return nil, err2
	}


	instanceInformation, err := v.client.Instances.Get(
		v.opts.Project,
		v.opts.Zone,
		v.instanceName).Do()
	if err != nil {
		fmt.Fprintf(v.debugFile,"Unable to get instance information:%v\n",err);
	}

	var targetDeviceName string
	fmt.Fprintf(v.debugFile,"Disk on machine are %v",instanceInformation.Disks);
	for _, disk := range instanceInformation.Disks {
		if strings.HasSuffix(disk.Source,v.opts.Name) {
			targetDeviceName = disk.DeviceName
			break;
		}
	}
	if len(targetDeviceName)==0 {
		fmt.Fprintf(v.debugFile,"Unable to find target device,");
		return nil,errors.New("Unable to find GCE target device");
	}
	
	fmt.Fprintf(v.debugFile,"Disk attached at /dev/disk/by-id/google-%s\n",targetDeviceName);
	glog.V(2).Info("Attached device on host");
	dev, err := losetup.Attach(
		fmt.Sprintf("/dev/disk/by-id/google-%s", targetDeviceName),
		0,
		false,
	)	
	glog.V(2).Info("Created loop device");
	if err != nil {
		fmt.Fprintf(v.debugFile,"Unable to create loop device\n",err);
		return nil, err
	}
	fmt.Fprintf(v.debugFile,"Loop Device located at:%s\n",dev.Path());
	v.loopDevice = &dev
	return &libvirtxml.DomainDisk{
		Type:   "block",
		Device: "disk",
		Source: &libvirtxml.DomainDiskSource{Device: dev.Path()},
		Driver: &libvirtxml.DomainDiskDriver{Name: "qemu", Type: "raw"},
	}, nil
}

func (v *gceDeviceVolume) waitUntilOperationIsFinished(operation *compute.Operation) error {
	opName := operation.Name
OpLoop:
	for {
		time.Sleep(100 * time.Millisecond)
		op, err := v.client.ZoneOperations.Get(
			v.opts.Project,
			v.opts.Zone,
			opName).Do()
		if err != nil {
			return err
		}
		fmt.Fprintf(v.debugFile,"Operation status:%v %v\n",op, err);
		switch op.Status {
		case "PENDING", "RUNNING":
			continue
		case "DONE":
			if op.Error != nil {
				return err
			}
			break OpLoop
		default:
			glog.Errorf("Unknown status %q: %+v", op.Status, op)
			return nil
		}
	}
	return nil
}

func (v *gceDeviceVolume) Teardown() error {
	fmt.Fprintf(v.debugFile,"Tearing down device\n");
	if v.loopDevice!=nil {
		fmt.Fprintf(v.debugFile,"Tearing down device Loop Device\n");
		glog.V(2).Info("Detaching loop device");
		err := v.loopDevice.Detach();
		if err != nil {
			return err
		}
	}
	fmt.Fprintf(v.debugFile,"Detaching GCE Disk\n");
	glog.V(2).Info("Before detaching disk");
	operation, err := v.client.Instances.DetachDisk(
		v.opts.Project,
		v.opts.Zone,
		v.instanceName,
		v.opts.Name).Do()
	if err != nil {
		return err
	}
	err2 := v.waitUntilOperationIsFinished(operation)
	if err2 != nil {
		return err2
	}
	glog.V(2).Info("Done detaching disk");
	return nil
}

func init() {
	
	glog.V(2).Info("Initializing GCE flex module");
	AddFlexvolumeSource("gce", newGCEDeviceVolume)
}

// TODO: this file needs a test
