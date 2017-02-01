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

package dtstats

import "bufio"
import "bytes"
import "fmt"
import "io"
import "log"
import "net"
import "os"
import "regexp"
import "sort"
import "strconv"
import "strings"
import "time"
import "encoding/binary"

import "github.com/miekg/dns"
import "github.com/golang/protobuf/proto"


type StatOutput struct {
    outputChannel   chan []byte
    wait            chan bool
    writer          *bufio.Writer
}

type Pair struct {
    key string
    val int
}
type PairList []Pair

type Inspect struct {
    name string
    match string
    mtype int
}

const PREFIX = "dnstap."
const INSPECT = "/opt/dns/etc/INSPECT.dnstap"
const REPORT_DIR = "/opt/dns/stats/spool"

var TS int64 = 0
var TS_first int64 = 0

func (p PairList) Len() int { return len(p) }
func (p PairList) Less(i, j int) bool { return p[i].val < p[j].val }
func (p PairList) Swap(i, j int){ p[i], p[j] = p[j], p[i] }

func SortByValue(m *map[string]int) PairList {
    pl := make(PairList, len(*m))
    i := 0
    for k, v := range *m {
        pl[i] = Pair{k, v}
        i++
    }
    sort.Sort(sort.Reverse(PairList(pl)))
    return pl
}

func ReportStats(data_name string, m *map[string] int, minval int, nmax int) *bytes.Buffer {
    var b bytes.Buffer
    host, _ := os.Hostname()

    var pl = SortByValue(m)
    //b.WriteString(fmt.Sprintf("dom %T\n", dom))
    //b.WriteString(fmt.Sprintf("pl %T\n", pl))

    var c = 0
    var re = regexp.MustCompile("([ ,=])")
    for _, p := range pl {
        //b.WriteString(fmt.Sprintf("i %T\n", i))
        //b.WriteString(fmt.Sprintf("p %T\n", p))
        var k = p.key
        var v = p.val
        if v < minval {
            break
        }
        c++
        if nmax > 0 && c >= nmax { break }
        var kq = fmt.Sprintf("%+q", k)
        // Sigh, omit double quotes from the string, added by "%+q"
        kq = kq[1:len(kq)-1]
        // Escape these chars: space, comma, equals sign
        // for InfluxDB tag value compatibility
        kq = re.ReplaceAllString(kq, "\\$1")

        b.WriteString(fmt.Sprintf("%s%s,host=%s,key=%s value=%d %d\n",
            PREFIX, data_name, host, kq, v, TS))
    }
    b.WriteString(fmt.Sprintf("%s%s.stats,host=%s,key=count_unique value=%d %d\n",
        PREFIX, data_name, host, len(*m), TS))
    b.WriteString(fmt.Sprintf("%s%s.stats,host=%s,key=count_threshold value=%d %d\n",
        PREFIX, data_name, host, c, TS))
    b.WriteString(fmt.Sprintf("%s%s.stats,host=%s,key=threshold value=%d %d\n",
        PREFIX, data_name, host, minval, TS))
    return &b
}

func NewStatOutput(writer io.Writer) (o *StatOutput) {
    o = new(StatOutput)
    o.outputChannel = make(chan []byte, outputChannelSize)
    o.writer = bufio.NewWriter(writer)
    o.wait = make(chan bool)
    return
}

func NewStatOutputFromFilename(fname string) (o *StatOutput, err error) {
    if fname == "" || fname == "-" {
        return NewStatOutput(os.Stdout), nil
    }
    writer, err := os.Create(fname)
    if err != nil {
        return
    }
    return NewStatOutput(writer), nil
}

func (o *StatOutput) GetOutputChannel() (chan []byte) {
    return o.outputChannel
}

func (o *StatOutput) RunOutputLoop() {
    var cq_INSPECT = make([]Inspect, 0)
    var cq_CNT = make(map[string] int)

    f_ins, _ := os.Open(INSPECT)
    defer f_ins.Close()
    scn := bufio.NewScanner(f_ins)
    scn.Split(bufio.ScanLines)
    for scn.Scan() {
        line := scn.Text()

        // Trim whitespace, skip empty lines and comments
        line = strings.TrimSpace(line)
        if len(line) < 1 || strings.HasPrefix(line, "#") {
            continue
        }

        // Combine sequential TAB chars into one
        l1 := len(line)
        l2 := l1
        for true {
            line = strings.Replace(line, "\t\t", "\t", -1)
            l2 = len(line)
            if l2 == l1 { break }
            l1 = l2
        }
        // name, prefix/suffix, stringmatch
        cline := strings.Split(line, "\t")
        if len(cline) != 3 {
            // silently discard illegal lines
            continue
        }
        if cline[1] == "prefix" {
            cq_INSPECT = append(cq_INSPECT, Inspect{cline[0], cline[2], 1})
        } else if cline[1] == "suffix" {
            cq_INSPECT = append(cq_INSPECT, Inspect{cline[0], cline[2], 2})
        }
        // Other match types than prefix/suffix are silently discarded
    }

    var cq, cq_f, cr, cr_f, rq, rq_f, rr, rr_f int
    var cr_dt_ok, cr_dt_no, cr_tc, rr_tc int

    cq, cq_f, cr, cr_f, rq, rq_f, rr, rr_f = 0, 0, 0, 0, 0, 0, 0, 0
    cr_dt_ok, cr_dt_no, cr_tc, rr_tc = 0, 0, 0, 0

    var cq_sz = make(map[string] int)
    var cq_src = make(map[string] int)
    var cq_port = make(map[string] int)
    var cq_name = make(map[string] int)
    var cq_name_p = make(map[string] int)
    var cq_type = make(map[string] int)
    var cq_any_src = make(map[string] int)
    var cq_any_name = make(map[string] int)
    var cq_any_name_p = make(map[string] int)

    var cr_sz = make(map[string] int)
    var cr_rcode = make(map[string] int)
    var cr_servfail_src = make(map[string] int)
    var cr_servfail_name = make(map[string] int)
    var cr_servfail_name_p = make(map[string] int)
    var cr_nxdomain_src = make(map[string] int)
    var cr_nxdomain_name = make(map[string] int)
    var cr_nxdomain_name_p = make(map[string] int)
    var cr_tc_src = make(map[string] int)
    var cr_slow_src = make(map[string] int)
    var cr_slow_name = make(map[string] int)
    var cr_slow_name_p = make(map[string] int)

    var rq_zone = make(map[string] int)
    var rq_type = make(map[string] int)
    var rq_srv = make(map[string] int)
    var rq_name = make(map[string] int)
    var rq_name_p = make(map[string] int)

    var rr_rcode = make(map[string] int)
    var rr_servfail_name = make(map[string] int)
    var rr_servfail_name_p = make(map[string] int)
    var rr_nxdomain_name = make(map[string] int)
    var rr_nxdomain_name_p = make(map[string] int)
    var rr_slow_srv = make(map[string] int)
    var rr_slow_name = make(map[string] int)
    var rr_slow_name_p = make(map[string] int)
    var rr_slow_zone = make(map[string] int)

    var cq_src_track = make(map[string] time.Time)

    var dt = &Dnstap{}
    for frame := range o.outputChannel {
        if err := proto.Unmarshal(frame, dt); err != nil {
            log.Fatalf("analyzer.StatOutput: proto.Unmarshal() failed: %s\n", err)
            break
        }

        if *dt.Type != Dnstap_MESSAGE {
            continue
        }

        var m = *dt.Message
        switch *m.Type {

        case Message_CLIENT_QUERY:
            cq++

            var sz = fmt.Sprintf("%04d", (binary.Size(m.QueryMessage)/50)*50 + 50)
            cq_sz[sz]++

            var qa = net.IP(m.QueryAddress).String()
            cq_src[qa]++

            var msg = new(dns.Msg)
            var err = msg.Unpack(m.QueryMessage)
            if err != nil {
                cq_f++
                // log.Printf("CQ unpack failed: %s", err.Error())
                continue
            }

            if (len(msg.Question) == 0) {
                // log.Printf("CQ question empty!")
                continue
            }

            var tq = time.Unix(int64(*m.QueryTimeSec), int64(*m.QueryTimeNsec)).UTC()

            var ts_now = tq.Unix()
            var ts_60 int64 = (ts_now / 60) * 60
            if TS == 0 {
                TS = ts_60
                TS_first = ts_now
            } else if TS < ts_60 && ts_now < TS_first+10 {
                TS = ts_60
            }

            var qp = strconv.Itoa(int(*m.QueryPort))
            var qid = strconv.Itoa(int(msg.MsgHdr.Id))
            var cq_key = fmt.Sprintf("%s:%s:%s", qa, qp, qid)
            cq_port[qp]++

            var q = msg.Question[0]
            qtype_s := dns.TypeToString[q.Qtype]
            if len(qtype_s) == 0 { qtype_s = "Unknown" }
            cq_type[qtype_s]++

            var name = q.Name
            var nlist = strings.Split(name, ".")
            var name_p = "."
            if len(nlist) > 1 {
                nlist = nlist[1:]
                if len(nlist) == 1 { nlist = append(nlist, "") }
                name_p = strings.Join(nlist, ".")
            }

            cq_name[name]++
            cq_name_p[name_p]++
            cq_src_track[cq_key] = tq

            if q.Qtype == dns.TypeANY {
                cq_any_src[qa]++
                cq_any_name[name]++
                cq_any_name_p[name_p]++
            }

            // Check if query matches any element in cq_INSPECT
            for _, insp := range cq_INSPECT {
                insp_m := false
                if insp.mtype == 1 {
                    if strings.HasPrefix(name, insp.match) { insp_m = true }
                } else if insp.mtype == 2 {
                    if strings.HasSuffix(name, insp.match) { insp_m = true }
                }
                if insp_m {
                    cq_CNT[ insp.name + "\t" + qa + "\t" + name ]++
                }
            }


		case Message_CLIENT_RESPONSE:
            cr++

            var sz = fmt.Sprintf("%04d", (binary.Size(m.ResponseMessage)/50)*50 + 50)
            cr_sz[sz]++

            var msg = new(dns.Msg)
            var err = msg.Unpack(m.ResponseMessage)
            if err != nil {
                cr_f++
                // log.Printf("CR unpack failed: %s", err.Error())
                match, _ := regexp.MatchString(".*truncated message.*", err.Error())
                if match {
                    cr_tc++
                    if m.QueryAddress != nil {
                        cr_tc_src[net.IP(m.QueryAddress).String()]++
                    }
                }
                continue
            }

            if (len(msg.Question) == 0) {
                // log.Printf("CR question empty!")
                continue
            }

            var qa = net.IP(m.QueryAddress).String()
            var qp = strconv.Itoa(int(*m.QueryPort))
            var qid = strconv.Itoa(int(msg.MsgHdr.Id))
            var cq_key = fmt.Sprintf("%s:%s:%s", qa, qp, qid)
            var q = msg.Question[0]
            var name = q.Name
            var nlist = strings.Split(name, ".")
            var name_p = "."
            if len(nlist) > 1 {
                nlist = nlist[1:]
                if len(nlist) == 1 { nlist = append(nlist, "") }
                name_p = strings.Join(nlist, ".")
            }

            var rcode = msg.MsgHdr.Rcode
            cr_rcode[dns.RcodeToString[rcode]]++

            if rcode == dns.RcodeServerFailure {
                cr_servfail_src[qa]++
                cr_servfail_name[name]++
                cr_servfail_name_p[name_p]++
            }
            if rcode == dns.RcodeNameError {
                cr_nxdomain_src[qa]++
                cr_nxdomain_name[name]++
                cr_nxdomain_name_p[name_p]++
            }

            var tr = time.Unix(int64(*m.ResponseTimeSec), int64(*m.ResponseTimeNsec)).UTC()
            tq, ok := cq_src_track[cq_key]
            if ok {
                cr_dt_ok++
                var t_diff = tr.Sub(tq)

                /* nanoseconds, 1000000 = 1ms */
                if t_diff > 1000 * 1000000 {
                    // Delay more than 1s
                    // log.Printf("Slow CR: %d ms %s", t_diff / 1000000, name)
                    cr_slow_src[qa]++
                    cr_slow_name[name]++
                    cr_slow_name_p[name_p]++
                }
            } else {
                cr_dt_no++
            }


        case Message_RESOLVER_QUERY:
            rq++

            zone, _, err := dns.UnpackDomainName(m.QueryZone, 0)
            if err != nil {
                log.Printf("RQ zone name unpack failed: %s", err.Error())
                continue
            }
            rq_zone[zone]++

            var msg = new(dns.Msg)
            err = msg.Unpack(m.QueryMessage)
            if err != nil {
                rq_f++
                // log.Printf("RQ unpack failed: %s", err.Error())
                continue
            }

            // var qid = strconv.Itoa(int(msg.MsgHdr.Id))

            var ra = net.IP(m.ResponseAddress).String()
            var q = msg.Question[0]
            var qtype_s = dns.TypeToString[q.Qtype]
            if len(qtype_s) == 0 { qtype_s = "Unknown" }
            rq_type[qtype_s]++

            var name = q.Name
            var nlist = strings.Split(name, ".")
            var name_p = "."
            if len(nlist) > 1 {
                nlist = nlist[1:]
                if len(nlist) == 1 { nlist = append(nlist, "") }
                name_p = strings.Join(nlist, ".")
            }

            rq_srv[ra]++
            rq_name[name]++
            rq_name_p[name_p]++


        case Message_RESOLVER_RESPONSE:
            rr++

            var tq = time.Unix(int64(*m.QueryTimeSec), int64(*m.QueryTimeNsec)).UTC()
            var tr = time.Unix(int64(*m.ResponseTimeSec), int64(*m.ResponseTimeNsec)).UTC()
            var t_diff = tr.Sub(tq)
            // log.Printf("RR zone %s delay %d", zone, t_diff)

            var msg = new(dns.Msg)
            var err = msg.Unpack(m.ResponseMessage)
            if err != nil {
                rr_f++
                // Probably truncated msg
                // log.Printf("RR unpack failed: %s", err.Error())
                match, _ := regexp.MatchString(".*truncated message.*", err.Error())
                if match { rr_tc++ }
                continue
            }

            if (len(msg.Question) == 0) {
                // log.Printf("RR question empty!")
                continue
            }

            var q = msg.Question[0]
            var name = q.Name
            var nlist = strings.Split(name, ".")
            var name_p = "."
            if len(nlist) > 1 {
                nlist = nlist[1:]
                if len(nlist) == 1 { nlist = append(nlist, "") }
                name_p = strings.Join(nlist, ".")
            }

            var rcode = msg.MsgHdr.Rcode
            rr_rcode[dns.RcodeToString[rcode]]++

            if rcode == dns.RcodeServerFailure {
                rr_servfail_name[name]++
                rr_servfail_name_p[name_p]++
            }
            if rcode == dns.RcodeNameError {
                rr_nxdomain_name[name]++
                rr_nxdomain_name_p[name_p]++
            }

            /* nanoseconds, 1000000 = 1ms */
            if t_diff > 500*1000000 {
                // Delay more than 500ms
                // log.Printf("Slow RR: %d ms %s", t_diff / 1000000, name)

                zone, _, err := dns.UnpackDomainName(m.QueryZone, 0)
                if err != nil {
                    log.Printf("RR zone name unpack failed: %s", err.Error())
                    continue
                }

                // var qid = strconv.Itoa(int(msg.MsgHdr.Id))
                if (len(msg.Question) == 0) {
                    // Question is empty, truncated and non-parsed msg
                    continue
                }

                var ra = net.IP(m.ResponseAddress).String()
                var q = msg.Question[0]
                var name = q.Name
                var nlist = strings.Split(name, ".")
                var name_p = "."
                if len(nlist) > 1 {
                    nlist = nlist[1:]
                    if len(nlist) == 1 { nlist = append(nlist, "") }
                    name_p = strings.Join(nlist, ".")
                }

                rr_slow_srv[ra]++
                rr_slow_name[name]++
                rr_slow_name_p[name_p]++
                rr_slow_zone[zone]++
            }
        } // END switch *m.Type
    } // END for frame := range o.outputChannel

    o.writer.Flush()
    host, _ := os.Hostname()

    var s bytes.Buffer

    s.WriteString(fmt.Sprintf("dnstap.client_query,host=%s,key=count value=%d %d\n", host, cq, TS))
    s.WriteString(fmt.Sprintf("dnstap.client_response,host=%s,key=count value=%d %d\n", host, cr, TS))
    s.WriteString(fmt.Sprintf("dnstap.resolver_query,host=%s,key=count value=%d %d\n", host, rq, TS))
    s.WriteString(fmt.Sprintf("dnstap.resolver_response,host=%s,key=count value=%d %d\n", host, rr, TS))

    s.WriteString(fmt.Sprintf("dnstap.client_query.fail,host=%s,key=count value=%d %d\n", host, cq_f, TS))
    s.WriteString(fmt.Sprintf("dnstap.client_response.fail,host=%s,key=count value=%d %d\n", host, cr_f, TS))
    s.WriteString(fmt.Sprintf("dnstap.resolver_query.fail,host=%s,key=count value=%d %d\n", host, rq_f, TS))
    s.WriteString(fmt.Sprintf("dnstap.resolver_response.fail,host=%s,key=count value=%d %d\n", host, rr_f, TS))

    s.WriteString(fmt.Sprintf("dnstap.client_response.tc,host=%s,key=count value=%d %d\n", host, cr_tc, TS))
    s.WriteString(fmt.Sprintf("dnstap.resolver_response.tc,host=%s,key=count value=%d %d\n", host, rr_tc, TS))
    s.WriteString(fmt.Sprintf("dnstap.client_response.track_delay,host=%s,key=success value=%d %d\n", host, cr_dt_ok, TS))
    s.WriteString(fmt.Sprintf("dnstap.client_response.track_delay,host=%s,key=failure value=%d %d\n", host, cr_dt_no, TS))
    o.writer.Write(s.Bytes())
    o.writer.Flush()

    var b *bytes.Buffer

    b = ReportStats("client_query.size", &cq_sz, 0, 0)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_query.type", &cq_type, 0, 0)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_query.port", &cq_port, cq/500, 20)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_query.src", &cq_src, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_query.name", &cq_name, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_query.name_parent", &cq_name_p, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_query.any.src", &cq_any_src, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_query.any.name", &cq_any_name, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_query.any.name_parent", &cq_any_name_p, 120, 40)
    o.writer.Write(b.Bytes())

    b = ReportStats("client_response.size", &cr_sz, 0, 0)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_response.rcode", &cr_rcode, 0, 0)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_response.tc.src", &cr_tc_src, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_response.servfail.src", &cr_servfail_src, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_response.servfail.name", &cr_servfail_name, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_response.servfail.name_parent", &cr_servfail_name_p, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_response.nxdomain.src", &cr_nxdomain_src, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_response.nxdomain.name", &cr_nxdomain_name, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_response.nxdomain.name_parent", &cr_nxdomain_name_p, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_response.slow.src", &cr_slow_src, 30, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_response.slow.name", &cr_slow_name, 30, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("client_response.slow.name_parent", &cr_slow_name_p, 30, 40)
    o.writer.Write(b.Bytes())

    b = ReportStats("resolver_query.type", &rq_type, 0, 0)
    o.writer.Write(b.Bytes())
    b = ReportStats("resolver_query.zone", &rq_zone, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("resolver_query.srv", &rq_srv, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("resolver_query.name", &rq_name, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("resolver_query.name_parent", &rq_name_p, 120, 40)
    o.writer.Write(b.Bytes())

    b = ReportStats("resolver_response.rcode", &rr_rcode, 0, 0)
    o.writer.Write(b.Bytes())
    b = ReportStats("resolver_response.servfail.name", &rr_servfail_name, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("resolver_response.servfail.name_parent", &rr_servfail_name_p, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("resolver_response.nxdomain.name", &rr_nxdomain_name, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("resolver_response.nxdomain.name_parent", &rr_nxdomain_name_p, 120, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("resolver_response.slow.server", &rr_slow_srv, 30, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("resolver_response.slow.name", &rr_slow_name, 30, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("resolver_response.slow.name_parent", &rr_slow_name_p, 30, 40)
    o.writer.Write(b.Bytes())
    b = ReportStats("resolver_response.slow.zone", &rr_slow_zone, 30, 40)
    o.writer.Write(b.Bytes())

    rep_file := fmt.Sprintf("%s/INSPECT-%s-%d.report", REPORT_DIR, host, TS)
    rep_tmp := rep_file+".tmp"
    rep_f, _ := os.Create(rep_tmp)
    for k, v := range cq_CNT {
        rep_f.WriteString(strconv.Itoa(v)+"\t"+k+"\n")
    }
    rep_f.Sync()
    rep_f.Close()
    os.Rename(rep_tmp, rep_file)

    o.writer.Flush()
    close(o.wait)
}

func (o *StatOutput) Close() {
    close(o.outputChannel)
    <-o.wait
    o.writer.Flush()
}

// EOF
