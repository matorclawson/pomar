package hostpolicy

import "os"

// DescriptorACLSafe reports the existing conservative kernel ACL check for
// this opened object. Unknown/unsupported metadata is false. It establishes
// neither ownership, pathname custody nor authority to use the object's bytes.
func DescriptorACLSafe(f *os.File) bool {
	if f == nil {
		return false
	}
	return kernelACLSafe(f)
}
