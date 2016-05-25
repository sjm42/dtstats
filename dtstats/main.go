/*
 * Copyright (c) 2016 Sami J. Mäkinen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import "flag"
import "fmt"
import "log"
import "os"
import "os/signal"
import "runtime"

import "github.com/sjm42/dtstats"

var
(
    fR = flag.String("r", "", "read dnstap data from file")
    fW = flag.String("w", "-", "write statistics to file")
)

func usage() {
    fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
    flag.PrintDefaults()
}

func main() {
    var err error
    var i dtstats.Input
    var o dtstats.Output

    runtime.GOMAXPROCS(runtime.NumCPU())
    log.SetFlags(0)
    flag.Usage = usage
    flag.Parse()

    if *fR == "" {
        usage()
        os.Exit(1)
    }

    me := os.Args[0]
    o, err = dtstats.NewStatOutputFromFilename(*fW)
    if err != nil {
        fmt.Fprintf(os.Stderr, "%s: Cannot write output file: %s\n", me, err)
        os.Exit(1)
    }
    go o.RunOutputLoop()

    // Handle Ctrl-c (SIGINT)
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt)

    go func() {
        for _ = range c {
            o.Close()
            os.Exit(0)
        }
    }()

    if *fR != "" {
        i, err = dtstats.NewFrameStreamInputFromFilename(*fR)
        if err != nil {
            fmt.Fprintf(os.Stderr, "%s: Cannot read input file: %s\n", me, err)
            os.Exit(1)
        }
        // fmt.Fprintf(os.Stderr, "%s: reading input %s\n", me, *fR)
    }

    go i.ReadInto(o.GetOutputChannel())
    i.Wait()
    o.Close()
}

// EOF
