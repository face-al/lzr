/*
Copyright 2020 The Board of Trustees of The Leland Stanford Junior University

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
package lzr

import "sync/atomic"

// queued and written records, so main can tell when the writer has drained
var queuedWrites, doneWrites atomic.Int64

// queueWrite hands a record to the writer
func queueWrite(writingQueue chan *packet_metadata, packet *packet_metadata) {
	queuedWrites.Add(1)
	writingQueue <- packet
}

// MarkWritten is called by the writer after each record
func MarkWritten() {
	doneWrites.Add(1)
}

// WritesPending reports whether a queued record has not been written yet
func WritesPending() bool {
	return queuedWrites.Load() != doneWrites.Load()
}
