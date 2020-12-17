package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
)

func bindata_read(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	return buf.Bytes(), nil
}

var _templates_commands_tmpl = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xd4\x59\x4b\x73\xdb\x38\xf2\x3f\x93\x9f\x02\xc3\x72\xa6\xc8\x58\xa6\x32\xf3\x9f\xfa\x1f\xb4\xa3\xad\x4a\x9c\x87\x53\x15\x3b\x5e\x3f\x26\x07\xaf\x6b\x02\x91\x2d\x09\x65\x10\xa0\x41\xc8\x8f\xd5\xf0\xbb\x6f\x35\x00\xbe\x44\x4a\xb6\xb3\x7b\xd9\x8b\x4d\xa3\x01\x74\xf7\xaf\xdf\xf0\x78\x4c\x0e\x65\x0a\x64\x01\x02\x14\xd5\x90\x92\xd9\x23\x91\x39\x08\x9a\xb3\x83\x84\xb3\x03\x47\x90\x2a\x26\xef\xbf\x92\x93\xaf\x17\xe4\xc3\xfb\xcf\x17\xb1\x3f\x1e\x93\x73\x00\xb2\xd4\x3a\x2f\x26\xe3\xf1\x82\xe9\xe5\x6a\x16\x27\x32\x1b\x2b\xb6\x00\xad\xd9\x78\xf0\x16\xdf\xcf\x69\x72\x43\x17\x40\x32\xca\x84\xef\xb3\x2c\x97\x4a\x93\xd0\xf7\xd6\x6b\xc2\xe6\x24\xfe\x6c\x16\x8a\xf8\x63\xa6\x49\x59\x06\xf3\x4c\x07\xeb\x35\x01\x91\x92\xb2\xec\x6d\x3a\xd7\x8a\x89\x45\x81\x1b\x0b\xfb\xb9\x63\xf3\x05\xcb\x00\x77\x6a\x96\x41\x6b\x9b\xef\x05\xcf\x15\x7e\x9c\x70\x16\x74\xf7\xe7\x37\x8b\x31\x28\x25\x55\xb1\x41\x50\xc5\xf8\x5f\xa0\x24\x97\x8b\x31\x97\x8b\x0d\x62\x91\xcf\x7f\xf9\xbf\x71\x22\x67\x8a\x0e\x52\xee\x58\x0e\xca\x50\x64\x7e\xb3\x88\x99\x18\x2f\x7f\x15\x52\x8c\x17\x20\x34\x87\x8c\x8a\xf8\xee\xd7\xc0\x8f\x7c\x7f\xbd\x26\x29\xcc\x99\x00\x12\xe4\x54\xd1\xac\x08\x9c\xe6\x07\x44\x51\xb1\x00\x12\x7f\xcd\x35\x93\x82\xf2\x53\x43\x36\x54\x43\x66\x73\x02\xb7\x24\xbe\x78\xcc\x81\x04\x33\x29\x39\x50\x61\x0f\x7b\x5e\x92\xa5\xf1\x47\x4e\x17\x45\x18\xc5\xef\xa4\xe4\x21\xc2\x15\x1f\x7e\xf9\x7c\x42\x2d\x84\x23\x32\xa7\xbc\x80\x11\x31\x84\xf7\x50\x24\x8a\x19\x3e\x48\x8c\x1c\x07\xe0\x05\x74\xd9\x30\xa1\xff\xff\xb7\x21\x26\x9f\x91\x30\xc0\xe5\xcd\x4b\x39\xcc\xb9\xa4\x5b\x78\x7c\xb4\xa4\x21\x2e\xf1\x73\xf8\xf4\x6f\xb4\xde\x37\x70\x61\x10\x3c\x71\x5f\xed\xa0\x07\x8d\x17\xb6\x6c\xf6\x8d\x32\x0d\xca\x19\xab\x6f\x8c\x7b\xca\xf4\x01\x5e\x6f\xf7\x6d\x37\x8c\xa3\x9f\x2f\x31\xc4\x2c\xff\x0e\xcb\x84\xb3\xf8\x1c\xf4\xe1\xaa\xd0\x32\xb3\x3c\x92\x2c\x8d\x7c\xdf\x63\x73\xd2\xe6\x7b\x44\x0b\xf7\x49\xd6\xbe\xe7\x59\x57\x8b\xdf\x31\x91\x9e\xd6\xc7\xaa\xcd\x91\xef\xe1\xdd\x73\xa9\xc8\x9f\x23\xb2\xe0\x72\x46\x39\x92\xc8\x64\xea\xf4\x6b\xd6\x0a\xbc\x8e\x10\xd2\x61\xf6\x36\x4d\xf1\x33\x6c\xb6\x19\x92\xbd\xb7\x15\xb7\xeb\x35\xd9\x13\xa8\xf7\x64\x4a\x62\x07\x80\x59\xa4\x39\x33\x6b\x9f\xe4\xc6\xea\xe9\x6a\xc6\x59\x62\x68\xf6\xb3\xd9\xe1\xdf\x51\x45\xaa\xc3\x65\x79\xbe\x9a\x25\x32\xcb\xa8\x48\x09\xc6\x86\xef\xcf\x57\x22\x69\xd3\x41\xdd\x81\x42\x3c\xae\xae\x33\x9a\x5f\xd9\xec\x73\x6d\x7f\xa1\x52\x0a\xf4\x4a\x89\x21\xea\xda\x38\x81\x83\x62\xaf\x30\x17\x19\x91\xdc\x9d\xce\xd1\x06\xcf\x79\x5e\x90\x36\x2e\x15\x4c\x8c\x99\xdd\x1d\x9b\xce\x36\xb2\xfb\x57\x8a\x6f\xec\xbb\x3c\xfb\x52\xd3\xcb\x91\x95\xa6\xf2\xc8\xd2\xb7\xc0\x3a\xe9\x64\x8e\x89\x0f\x2f\x44\x01\xbf\x56\x7f\x59\x19\xc7\x63\xd2\xc5\xb5\x2c\xd1\xe9\x6a\x4c\x91\x5a\xfb\x9e\xef\xb5\x11\x1c\x3e\x10\xd6\x8c\xe3\x33\xb8\x5d\x31\x05\x69\x9d\xb5\xba\x37\x5b\x44\x46\xa4\x96\xdc\x7a\x24\x79\x6d\x12\x67\xfc\x07\xfe\x74\xd9\xff\x90\x8a\x23\x7a\x07\xef\x64\xfa\x48\xca\x72\x44\x66\xf8\xe1\x10\xad\x4e\x47\x24\x7c\xdd\xa4\xd6\x33\x28\x72\x29\x30\x88\x90\xe9\x99\x31\xa4\xc9\x2e\x78\xdc\xe4\x7a\x1b\x05\x4b\x2a\x52\x0e\xea\x94\xea\x25\xc2\x63\x22\xee\xc8\xae\x55\xe1\xe8\x7b\x18\x49\x83\x6e\x65\xcc\xd9\xbe\xc2\xde\x60\x3d\xba\x2c\x49\x40\xf6\x49\x8b\xec\x7b\x26\xaa\xbc\xc6\x5f\x30\x78\xcf\x56\xe2\x50\x8a\x39\x5b\xc4\x9f\x40\x9f\x2a\x39\x67\x1c\x30\x82\x72\x76\x79\xf6\x05\xb7\xaf\x14\xc7\xbd\xf6\xd4\xbe\x11\xd1\x30\x43\xd9\x5c\x32\x72\xa6\x66\x23\xb2\x67\x50\x34\xa6\xee\xe1\x8f\xd2\x36\x65\xc3\xee\x8c\x3f\x0b\x2c\x3b\x7a\x59\xa5\x5b\xc3\x6e\xea\xd0\x2d\xe2\x33\xc8\x39\x4d\x20\x5c\x29\x6e\x12\xd2\xf7\xf5\x77\x63\x48\x77\xda\x81\xb4\x5e\x7f\x2f\xbf\x9b\xd4\xd5\x90\x6a\x4b\x8f\xc8\x2f\x51\xc5\xba\xf2\xd1\x6e\x0e\xf3\x14\xdc\x56\x70\x1c\x72\x06\x42\xc7\xa8\xe5\x31\xe8\xa5\xc4\x2d\x61\x84\x0e\x8f\x32\x44\x7e\x27\xf2\x9e\xa5\x70\x5f\xdf\xdb\x15\xa8\xc7\x5a\x61\x64\x3e\x25\x0a\x6e\x31\x6b\xfd\x03\x49\xb6\x1c\x34\xf9\x78\x40\x29\xa7\x51\xbb\x7c\xb5\x18\x2c\x81\xa6\xa0\x86\x39\x1c\x19\xda\x4b\x58\x34\x98\xb5\x20\x7b\xa2\x3d\xf0\xba\xc1\x36\x99\x12\x97\xf0\x3f\x81\x46\x92\x09\x86\xbf\x88\x66\x9a\x9b\xb0\xdd\x2c\x80\x86\xb9\xf5\xfb\xd6\x35\x3f\x4d\x49\x75\xf8\x84\x71\x93\x1f\x8c\x82\xad\x66\xa4\x8f\xef\x33\x00\x9e\x67\x3a\x3e\xcf\x15\x13\x7a\x1e\x06\xaf\xee\x2c\x1e\x2d\x24\xa2\x9a\x4b\xbb\x5d\x18\x40\xfa\x39\x50\xbf\x80\x59\x85\xbc\xd7\x77\xd9\xc1\xd4\xe4\x40\x33\xf9\xe9\xa7\x29\x09\x02\x87\xcf\xa0\x54\x87\x52\x68\x10\xfa\x00\xd1\xac\x9a\x8d\x63\x48\x19\x75\x89\x2a\xc0\x5e\x21\x7d\x74\x1d\x0a\xde\x19\x35\xa2\xb4\x24\xc1\xa8\xb1\x39\xeb\x1d\xcc\xa5\x82\xb0\x95\x72\x46\xce\xec\x23\x64\x1e\xd9\x50\x2b\x72\x93\x02\x4d\x2d\x87\xdb\xf8\xbd\x0c\x23\x9b\xe3\x70\xf1\xa7\x29\x11\x8c\x5b\xb1\x5d\xfd\x13\x8c\x8f\xec\x0f\xdb\x24\xc7\xdf\x14\xcd\x43\x50\x6a\x44\x02\x0c\x39\x28\x34\x99\x53\xc6\x21\x35\x5e\x63\x64\xc2\x4a\x9c\x42\x22\x53\x48\xfb\x19\xd8\xb7\xec\x50\x92\xf8\x5c\x53\xbd\x2a\xcc\xf8\xf2\x3b\xf9\xed\xcd\x1b\xcb\xd9\x09\xe3\x52\xc2\xa5\xc8\xa8\x2a\x96\x94\x57\x59\x3d\xb4\x4a\xfc\xec\x38\x44\x7f\xeb\x89\xfe\x1c\xd9\xeb\x6b\x39\xd6\x7b\xe5\xee\x6e\xab\x62\xb0\x2e\xad\xcf\xed\x44\xe4\x03\xfe\x9a\x87\xc1\xd1\xc5\xc5\x29\x79\x95\x4e\xc8\xab\x22\x18\x6d\x2a\x58\x2f\x18\x7b\x46\x35\x56\x74\xae\x9b\x6a\x60\x0d\xf9\x16\x97\xb6\xd9\x11\x55\xaf\x34\xb7\x48\xda\x1b\xda\xfa\x57\xd8\x4f\x2d\xcd\x3a\xab\x80\x8e\x21\xb0\x95\x07\x35\xa7\x09\xac\x4b\x0c\xa0\x38\xec\x59\x2a\x6a\xa7\x1f\x97\xa9\x0d\x02\x1d\x29\x0c\x16\xd8\x77\x74\x1b\x3b\x97\xa3\xef\x4d\x03\x6b\x12\x74\xbb\x27\x7e\x51\x2b\x51\x77\x2d\xff\x8d\xa6\x22\xb2\x56\x33\x40\x51\xad\x21\xcb\x35\x4a\xf7\xc6\xf7\x4c\xc3\x5b\x2d\xfd\x6e\xa4\xb3\xd2\xc7\x6f\xed\x62\x51\xa7\x3c\xb7\x6b\x7f\xdf\xb7\x7e\xd1\x81\xc3\xf9\xee\x90\x76\x8d\x26\xff\x89\x9e\x3d\x05\xa3\x56\xd4\x0c\xc5\x41\xdf\xfb\x0f\xe5\x8a\xa7\x44\x48\x4d\x12\xca\x39\x71\x56\xaa\x9b\xc5\xca\xff\xf1\x27\x06\x33\x4d\xf4\x8a\x72\xd2\x72\x99\x8a\x92\x51\x9d\x2c\x6d\x87\xed\xb5\x6b\xb3\x59\x77\x86\x3f\xb6\xdf\x55\x6d\xf2\xec\x6d\x16\x28\xeb\xf7\x9f\x40\x9b\x4d\x7f\x50\xbe\xb2\xf1\x1d\x9b\xfc\xf8\xa0\x5d\x66\x3c\x07\x0e\x89\xb6\x19\xdc\x95\xb2\xb7\x9c\x9f\xe3\xa0\x2f\x70\xe4\xe8\xc4\xc4\x30\x16\xcf\x01\x63\x01\x9a\x54\x92\xdf\xa1\x2c\x16\x08\x87\x84\x67\x48\x6d\xb9\x8d\xd0\xb6\xc2\x5c\x60\x22\x34\xf2\x5d\x5d\xcf\x1e\x35\x98\x70\xfa\xf0\x90\x43\xa2\x21\x25\x7f\x11\x5b\x72\x48\xf0\xea\x16\xa3\x2d\x1a\x39\x4c\x7f\x44\xde\x6f\x4e\x42\x8b\x3d\x66\xac\x95\xaa\x25\xad\x6b\xa4\xa5\xba\xbb\xea\x3e\xc8\x64\x24\x1c\xb3\xdd\xa9\xba\x74\x6e\xb0\xab\x72\x9a\x0d\x5a\x92\x50\x81\xf8\x28\xa0\xc9\x92\xa4\x50\xa0\x73\x92\xc2\x5c\x35\x83\x84\xae\x0a\x20\xaf\x0a\xc2\x0a\x9b\xfa\x7a\x26\xdb\x8d\x45\x2d\x62\x6b\x4a\xf7\x3c\x6f\xa6\x80\xde\x34\xb4\xba\x1a\x7b\x65\xb7\x35\xc2\xbf\x34\xcb\x20\x3e\xe7\x00\x79\x68\xa7\x76\x4e\xb1\x22\xbf\xb6\xeb\x90\x48\x91\xd6\x19\x17\x53\xa6\x8b\xf2\xbf\x4f\x77\x86\x79\x17\x92\x13\xb8\x0f\x83\x63\xfa\xc0\xb2\x55\x56\xdd\x50\x10\x78\x48\x00\xd2\x76\xf5\x6b\xca\xc4\x46\x56\xdc\x98\x40\xcf\x60\xc1\x0a\xcc\xf4\x45\x77\x54\x1d\x75\xc6\xeb\xab\x6b\x13\x20\xf5\x8a\x99\x5c\x94\x94\xba\x9e\x20\xa4\xd4\x76\xde\x2f\xba\xb3\x89\xd9\x34\x25\x3f\x9b\x47\xaa\xf8\xd0\x52\x8c\x5e\x97\x05\x4c\x3a\xb3\x8a\x1d\x25\xcd\xa4\x67\x09\xf1\x85\x6b\x0d\x2d\xe5\x8b\x14\x8b\x89\xf3\x78\x75\x93\xca\x7b\x11\x0e\xbe\x8e\x8c\xfc\xba\x43\xe9\xcf\x4b\x53\xa2\xd5\x0a\xfc\x76\x49\xad\xe4\x77\x43\xe6\x74\x83\x77\x7b\x07\x8a\x50\x47\xdd\x2e\x19\xec\xe3\x85\x6b\xd0\x3a\xef\x30\x68\x66\x44\x6d\x2b\x22\xb8\xa1\x0b\x05\x9e\x27\xa6\x2e\x90\x04\x94\xa6\x4c\x10\xb8\x03\xa1\x89\x54\xb5\xfb\x63\xd7\x45\xac\xd1\x99\x58\xb4\x01\x0b\xde\x71\x99\xdc\xa0\x8f\x40\xb2\x32\x02\x22\x0e\xab\x02\x0a\x92\x4b\xdb\x78\x68\x49\x72\x50\x4c\xa6\x0c\x13\xf1\x23\x49\x96\x90\xdc\xfc\x00\xc7\xd2\x19\x1c\x5b\x4c\xa7\x58\x88\xea\x6c\x8c\x4c\x5b\xca\xb1\x67\x0b\xb2\x7b\x1c\xaa\x9e\x87\x70\x9b\xad\x9c\xe8\xfa\x36\x4c\x93\x2c\xdd\x02\x61\xcb\xad\xe2\xcb\xa2\xf1\x9d\x7a\x3e\x88\xdf\x72\x46\x51\xf7\x3a\xc2\xdd\xc2\x84\x5c\x75\x5e\x48\xbc\xce\x7c\xd3\x3b\xe5\x79\x86\x47\x8b\xc1\x66\xbf\x5e\x3d\x8b\x0c\x10\xda\x3e\x5e\xbf\xaa\xb9\xbd\xdb\xbc\xdc\xb8\x5e\xe5\xde\x28\xb6\x5a\x14\x13\x62\x11\x38\x66\x02\xf3\xc1\x09\xae\x61\xea\xe1\x20\x76\x16\xf2\xea\x8e\xb3\x95\x98\x10\x04\x3d\x44\x44\x5f\x77\xe0\x1c\x11\xaa\x4c\xe4\x5b\x50\x2a\xa3\xb4\x1b\xe3\x67\xb6\x4e\x7b\x0f\x9d\x11\x79\x87\x5c\xc8\xf1\x0a\x6f\x7d\x20\x65\x79\xdd\xef\x30\x06\x9a\x6c\xcf\xf3\xb8\x5c\xc4\x1f\xa9\xa6\x3c\x8c\xb0\x62\x60\x7d\x8a\xe2\xe3\x62\x11\x06\xa6\x7e\x98\xbe\x02\x3d\x34\xaa\xac\xe2\xb7\x8d\x63\xff\xc2\x3d\x6d\xaf\x75\xef\x97\x36\xc5\x63\x92\xe5\xa6\x60\x55\x8f\xe3\x8d\x12\xd5\x70\x16\x46\xdd\x17\xb0\x76\x65\x78\xe6\x43\x58\xd7\xfd\x87\xbd\xbf\xea\x78\xe0\x81\x66\x39\x87\xc2\x75\x9b\x7e\xb7\xef\x81\x07\x73\xff\x87\x6a\x93\xf3\xbb\xfa\xd0\xfe\x94\x04\xc4\x3c\x0d\xd5\x99\xcd\x29\x8e\x8d\x7e\x18\x91\x7d\x12\x18\xeb\xd6\xf2\xba\x60\x32\x8b\x80\xd6\xf9\xa7\x08\xfa\x05\x70\x47\x5c\x6e\x09\xcb\x6d\x51\xb9\x35\x28\x77\xc6\x64\x2f\x24\x37\x03\xaf\x1c\x0d\x0c\xd6\xbb\xc2\xf1\x99\xd1\x58\xa9\x71\xc4\xd2\x14\x44\xcd\xce\xfe\x39\x31\x9d\x47\x4d\x1a\x14\xc1\x99\x6a\x52\x1b\xd6\xee\x7a\x32\xc8\xb7\x85\xf6\x8f\x44\x76\xa5\x44\xff\x3d\xc1\xf3\x70\xf4\x1f\xb5\x07\xe2\x4f\xa0\x71\x43\xd8\x7f\x32\xb0\xd7\x5f\x0d\x4b\x58\x96\x93\x6b\x17\x87\x83\xed\xe6\x8e\x60\xbe\x14\x74\xc6\x01\x6b\x15\x36\xc8\x28\x50\x15\xd1\x65\x2f\xcb\xb6\xfb\xcd\xf8\x04\x20\x2d\xaa\xb9\x9d\x94\x25\x76\xf6\x4d\x9f\xf7\x67\xed\xc2\xcf\x9b\x9e\x9e\x4e\x70\x2f\x4d\x6b\x3b\x5e\x98\x9b\xa7\xe5\x1f\xc3\xcc\x26\xc0\xc4\xbd\x2f\x6c\x4c\x56\xf5\x44\xb1\xf1\xd6\xf1\x51\xaa\x0c\x3b\x4b\xe5\xbe\xc2\x1d\x6f\x1c\xbb\x98\xbb\x7b\x90\x73\xfb\x41\xa3\x61\x3b\xd4\x1e\xd9\x21\xe0\xf6\xb4\xce\x7e\x43\x83\x96\x5f\x87\xf7\xe0\x2b\x6c\x2b\x6d\x0d\xbe\xc7\x76\x78\x5c\x05\xbd\xa7\xe4\xe0\x9a\x4c\x6b\x27\xde\xc3\x06\xf2\xba\x61\xd8\xf1\xb0\x1d\x73\xe9\xa0\x3f\x0e\xff\x6b\xce\x99\xa0\x79\x1d\x7d\xf2\xff\x73\x4d\x35\xf6\xee\xb7\x17\x8a\x2e\x4f\xe3\xa5\x85\x99\x87\xa4\x6d\xbe\x30\x93\xb4\x3b\x9a\x97\x8f\xc4\xcd\x7d\x26\xf0\x6b\x50\x37\x26\xe1\xed\xae\xbb\xd3\x81\x9e\x1e\x89\xdb\xde\x84\x0a\xa8\x45\x15\x66\xa8\x60\xff\x95\xb5\x3d\xee\x0e\x59\xa8\xfb\xaf\x8c\x74\x13\xb0\x9e\x17\xfd\xef\x43\xe6\xdc\x27\x3e\x07\x6d\x72\xf9\x1e\x4b\x5d\x12\x7f\x12\xaa\xdd\x8d\xa0\x73\xda\x6d\xe9\x72\xc8\x11\x5b\xe6\x6b\x25\xc9\xfb\x9d\xcd\xdf\x0e\x2c\xdc\xab\x81\x19\x9c\x1b\xe5\xcb\x6e\x17\xb8\x51\x87\x6d\x75\x36\xdf\x9b\x83\x4c\xdd\x12\x0e\x77\x84\xee\x81\x32\x8c\xda\xbd\x5f\xe9\xff\x3b\x00\x00\xff\xff\xf6\x78\x6f\x5a\x19\x23\x00\x00")

func templates_commands_tmpl() ([]byte, error) {
	return bindata_read(
		_templates_commands_tmpl,
		"templates/commands.tmpl",
	)
}

var _templates_main_tmpl = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x9c\x53\x41\x4f\xf3\x38\x10\x3d\x27\xbf\x62\xb0\xd4\x55\xac\x2d\x0e\x7b\xad\x94\x43\x05\x29\x20\xc1\xa6\x2a\x85\x2b\x32\xc9\x24\xb5\x70\xec\xc8\x76\x0a\x12\xea\x7f\xff\xe4\xc4\x34\x50\x38\x7d\xbd\xc4\xe3\xf7\x3c\xf3\xe6\xcd\xb4\xe3\xe5\x2b\x6f\x10\x5a\x2e\x54\x1c\x8b\xb6\xd3\xc6\x41\x12\x03\x00\x90\xba\x75\x64\x3c\x49\xdd\x84\x93\xe9\x95\x13\x2d\x86\x48\xdb\x70\xb0\xce\x08\xd5\x58\x12\xc7\x11\x69\x84\xdb\xf5\x2f\xac\xd4\x6d\x6a\x44\x83\xce\x89\x54\x77\xa8\x78\x27\xce\x4b\x29\xce\x1b\x54\x68\xb8\xd3\x26\x2d\xa5\x20\x31\x8d\xe3\xba\x57\xe5\x20\x20\xa1\xf0\x31\xe4\x2b\xb5\xaa\x45\x03\x8b\x0c\xfe\x29\xa5\x60\x97\x43\x38\x42\xfe\xb7\xec\xba\xff\x79\x8b\x0b\x5f\xf9\xe3\x03\x98\x0f\xe0\x70\x20\xf3\x23\x23\x57\xfb\xb5\xc1\x5a\xbc\x2f\x26\x46\xae\xf6\xdf\x49\x4f\x68\xac\xd0\x6a\x48\xf3\x1f\xbb\x60\x17\x01\x3b\x8c\x1a\xa4\x60\xb7\x4a\xb8\x64\x14\x43\xe3\xe1\xb6\x91\xfa\x85\xcb\x95\xe4\x8d\x9d\x03\x1a\xe3\x35\x7a\xe6\x3d\x7f\xc5\xa5\xaa\xd6\xdc\x58\xbc\x9e\x38\x09\x1d\x5e\x89\x7a\xe0\x9e\x65\xa0\x84\x84\xa9\x11\xa9\x1b\xb6\xe2\x8e\xcb\x04\x8d\xa1\xa1\xf8\xf0\x49\x53\xd8\x16\x57\xc5\x02\x96\x55\x05\x06\x1b\x61\x1d\x1a\x28\x75\xdb\x72\x55\x59\xd8\xa1\x41\x36\x32\x7d\xe2\xec\xa8\x76\xb4\xaa\x37\xdc\x09\xad\x92\x1f\xbd\x43\x83\x6e\x5b\xdc\xdf\xad\x84\xc4\x35\x77\xbb\x84\x58\x3f\x20\x3f\x3a\xfa\x2b\x58\x1a\x74\x23\x36\x35\xf5\x37\x3d\x45\x5e\xe0\xb2\xaa\x46\x7d\x97\xa1\x8f\xc4\xdf\x6e\xb4\x76\xf4\x48\x58\xf6\x6e\xf7\x0b\x3c\xe2\xfe\xcc\xf2\x77\x2c\x7b\x87\x09\x8d\x0f\x61\x77\x4e\x75\xd7\x42\xa2\xf2\x3b\x31\xae\x25\x0d\xdf\x20\x12\xd5\xfe\x89\xcb\x1e\xfd\xe8\xb4\x65\xd7\xe8\x50\xed\x93\xb0\xc1\x6c\xab\x1f\xbb\x0e\x4d\x52\xb7\x8e\x3d\x74\x46\x28\x57\x27\x64\x66\x9f\x67\xf6\x79\xbd\xdc\xde\x90\xf9\xcf\x85\x82\xcf\x7a\x94\x4e\xd6\x7c\x16\x39\xcb\x80\x90\x2f\xf6\x18\x74\xbd\x51\x47\xfc\xcb\xc2\x05\xe4\xa4\x70\xca\x66\x36\x9d\x59\xe6\x74\x2b\xc9\x1c\x7a\x8b\xe6\x46\xb7\x78\x25\x4c\x42\xe7\x30\xa9\xbe\xd3\x6f\x68\x7e\x0c\x9c\x7e\x11\x77\xb4\xeb\x5b\x8e\xc9\x9b\x48\xd4\x10\xfe\xde\xec\xba\x28\x1e\x20\xcb\x80\xbc\x09\x55\xe9\x37\xeb\x3b\x88\xa2\x9d\x6e\x4f\x5c\x23\x37\xc5\x7d\x7e\xb5\xb9\x7d\xca\x09\x85\x7f\x4f\x81\xc1\x30\x1a\x47\x3e\xf3\xf0\x36\x0b\x66\x44\x21\xd7\xb7\x54\x8f\x0f\xf9\x66\xbd\x29\x56\xb7\x77\xf9\xf0\xe8\x10\x47\x51\xf0\xc4\x93\x63\x7f\x11\xe2\x93\x3a\xc4\xf7\xf6\x27\x00\x00\xff\xff\xdd\xe2\x20\x8f\xca\x04\x00\x00")

func templates_main_tmpl() ([]byte, error) {
	return bindata_read(
		_templates_main_tmpl,
		"templates/main.tmpl",
	)
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		return f()
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() ([]byte, error){
	"templates/commands.tmpl": templates_commands_tmpl,
	"templates/main.tmpl": templates_main_tmpl,
}
// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for name := range node.Children {
		rv = append(rv, name)
	}
	return rv, nil
}

type _bintree_t struct {
	Func func() ([]byte, error)
	Children map[string]*_bintree_t
}
var _bintree = &_bintree_t{nil, map[string]*_bintree_t{
	"templates": &_bintree_t{nil, map[string]*_bintree_t{
		"commands.tmpl": &_bintree_t{templates_commands_tmpl, map[string]*_bintree_t{
		}},
		"main.tmpl": &_bintree_t{templates_main_tmpl, map[string]*_bintree_t{
		}},
	}},
}}
