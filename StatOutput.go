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

const PREFIX = "dnstap."

var TS int64 = 0

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

func ReportStats(data_name string, m *map[string] int, minval int) *bytes.Buffer {
	var b bytes.Buffer
	host, _ := os.Hostname()

	pl := SortByValue(m)
	//b.WriteString(fmt.Sprintf("dom %T\n", dom))
	//b.WriteString(fmt.Sprintf("pl %T\n", pl))

	c := 0
	for _, p := range pl {
		//b.WriteString(fmt.Sprintf("i %T\n", i))
		//b.WriteString(fmt.Sprintf("p %T\n", p))
		k := p.key
		v := p.val
		if v < minval {
			break
		}
		c++
		b.WriteString(fmt.Sprintf("%s%s,host=%s,key=%s value=%d %d\n",
			PREFIX, data_name, host, k, v, TS))
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
	var cq, cr, rq, rr int
	var cr_d_ok, cr_d_no, cr_tc int

	cq_src := make(map[string] int)
	cq_name := make(map[string] int)
	cq_name_p := make(map[string] int)
	cq_any_src := make(map[string] int)
	cq_any_name := make(map[string] int)
	cq_any_name_p := make(map[string] int)

	cr_rcode := make(map[string] int)
	cr_servfail_src := make(map[string] int)
	cr_servfail_name := make(map[string] int)
	cr_servfail_name_p := make(map[string] int)
	cr_nxdomain_src := make(map[string] int)
	cr_nxdomain_name := make(map[string] int)
	cr_nxdomain_name_p := make(map[string] int)
	cr_tc_src := make(map[string] int)
	cr_slow_src := make(map[string] int)
	cr_slow_name := make(map[string] int)
	cr_slow_name_p := make(map[string] int)

	rq_zone := make(map[string] int)
	rq_srv := make(map[string] int)
	// rq_name := make(map[string] int)
	// rq_name_p := make(map[string] int)

	rr_slow_srv := make(map[string] int)
	rr_slow_name := make(map[string] int)
	rr_slow_name_p := make(map[string] int)
	rr_slow_zone := make(map[string] int)

	cq_src_track := make(map[string] time.Time)

	dt := &Dnstap{}
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

			qa := net.IP(m.QueryAddress).String()
			cq_src[qa]++

			msg := new(dns.Msg)
			err := msg.Unpack(m.QueryMessage)
			if err != nil {
				// log.Printf("CQ unpack failed: %s", err.Error())
				continue
			}

			if (len(msg.Question) == 0) {
				// log.Printf("CQ question empty!")
				continue
			}

			tq := time.Unix(int64(*m.QueryTimeSec), int64(*m.QueryTimeNsec)).UTC()
			if TS == 0 {
				// Use 60sec resolution
				TS = (tq.Unix() / 60) * 60
			}

			qp := strconv.Itoa(int(*m.QueryPort))
			qid := strconv.Itoa(int(msg.MsgHdr.Id))
			cq_key := fmt.Sprintf("%s:%s:%s", qa, qp, qid)

			q := msg.Question[0]
			name := q.Name
			nlist := strings.Split(name, ".")
			name_p := "."
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


		case Message_CLIENT_RESPONSE:
			cr++

			msg := new(dns.Msg)
			err := msg.Unpack(m.ResponseMessage)
			//log.Printf("CR unpack failed: %s", err.Error())
			if err != nil {
				match, _ := regexp.MatchString(".*truncated message.*",
					err.Error())
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

			qa := net.IP(m.QueryAddress).String()
			qp := strconv.Itoa(int(*m.QueryPort))
			qid := strconv.Itoa(int(msg.MsgHdr.Id))
			cq_key := fmt.Sprintf("%s:%s:%s", qa, qp, qid)
			q := msg.Question[0]
			name := q.Name
			nlist := strings.Split(name, ".")
			name_p := "."
			if len(nlist) > 1 {
				nlist = nlist[1:]
				if len(nlist) == 1 { nlist = append(nlist, "") }
				name_p = strings.Join(nlist, ".")
			}

			rcode := msg.MsgHdr.Rcode
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

			tr := time.Unix(int64(*m.ResponseTimeSec), int64(*m.ResponseTimeNsec)).UTC()
			tq, ok := cq_src_track[cq_key]
			if ok {
				cr_d_ok++
				t_diff := tr.Sub(tq)

				/* nanoseconds, 1000000 = 1ms */
				if t_diff > 1000 * 1000000 {
					// Delay more than 1s
					// log.Printf("Slow CR: %d ms %s", t_diff / 1000000, name)
					cr_slow_src[qa]++
					cr_slow_name[name]++
					cr_slow_name_p[name_p]++
				}
			} else {
				cr_d_no++
			}


		case Message_RESOLVER_QUERY:
			rq++

			zone, _, err := dns.UnpackDomainName(m.QueryZone, 0)
			if err != nil {
				log.Printf("RQ zone name unpack failed: %s", err.Error())
				continue
			}
			rq_zone[zone]++

			/*
			msg := new(dns.Msg)
			err := msg.Unpack(m.QueryMessage)
			if err != nil {
				log.Printf("RQ unpack failed: %s", err.Error())
				continue
			}

			// qid := strconv.Itoa(int(msg.MsgHdr.Id))

			ra := net.IP(m.ResponseAddress).String()
			q := msg.Question[0]
			name := q.Name
			nlist := strings.Split(name, ".")
			name_p := "."
			if len(nlist) > 1 {
				nlist = nlist[1:]
				if len(nlist) == 1 { nlist = append(nlist, "") }
				name_p = strings.Join(nlist, ".")
			}

			rq_srv[ra]++
			rq_name[name]++
			rq_name_p[name_p]++
			*/


		case Message_RESOLVER_RESPONSE:
			rr++

			tq := time.Unix(int64(*m.QueryTimeSec), int64(*m.QueryTimeNsec)).UTC()
			tr := time.Unix(int64(*m.ResponseTimeSec), int64(*m.ResponseTimeNsec)).UTC()
			t_diff := tr.Sub(tq)
			// log.Printf("RR zone %s delay %d", zone, t_diff)

			/* nanoseconds, 1000000 = 1ms */
			if t_diff > 1000*1000000 {
				// Delay more than 1s
				// log.Printf("Slow RR: %d ms %s", t_diff / 1000000, name)

				msg := new(dns.Msg)
				err := msg.Unpack(m.ResponseMessage)
				if err != nil {
					// Probably truncated msg
					// log.Printf("RR unpack failed: %s", err.Error())
					continue
				}

				zone, _, err := dns.UnpackDomainName(m.QueryZone, 0)
				if err != nil {
					log.Printf("RR zone name unpack failed: %s", err.Error())
					continue
				}

				// qid := strconv.Itoa(int(msg.MsgHdr.Id))
				if (len(msg.Question) == 0) {
					// Question is empty, truncated and non-parsed msg
					continue
				}

				ra := net.IP(m.ResponseAddress).String()
				q := msg.Question[0]
				name := q.Name
				nlist := strings.Split(name, ".")
				name_p := "."
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
		}
	}

	o.writer.Flush()
	host, _ := os.Hostname()

	var s bytes.Buffer

	s.WriteString(fmt.Sprintf("dnstap.client_query,host=%s,key=count value=%d %d\n", host, cq, TS))
	s.WriteString(fmt.Sprintf("dnstap.client_response,host=%s,key=count value=%d %d\n", host, cr, TS))
	s.WriteString(fmt.Sprintf("dnstap.resolver_query,host=%s,key=count value=%d %d\n", host, rq, TS))
	s.WriteString(fmt.Sprintf("dnstap.resolver_response,host=%s,key=count value=%d %d\n", host, rr, TS))
	s.WriteString(fmt.Sprintf("dnstap.client_response.tc,host=%s,key=count value=%d %d\n", host, cr_tc, TS))
	s.WriteString(fmt.Sprintf("dnstap.client_response.track_delay,host=%s,key=success value=%d %d\n", host, cr_d_ok, TS))
	s.WriteString(fmt.Sprintf("dnstap.client_response.track_delay,host=%s,key=failure value=%d %d\n", host, cr_d_no, TS))
	o.writer.Write(s.Bytes())
	o.writer.Flush()

	var b *bytes.Buffer

	b = ReportStats("client_query.src", &cq_src, 120)
	o.writer.Write(b.Bytes())

	b = ReportStats("client_query.name", &cq_name, 120)
	o.writer.Write(b.Bytes())
	b = ReportStats("client_query.name_parent", &cq_name_p, 120)
	o.writer.Write(b.Bytes())

	b = ReportStats("client_query.any.src", &cq_any_src, 60)
	o.writer.Write(b.Bytes())
	b = ReportStats("client_query.any.name", &cq_any_name, 30)
	o.writer.Write(b.Bytes())
	b = ReportStats("client_query.any.name_parent", &cq_any_name_p, 30)
	o.writer.Write(b.Bytes())

	b = ReportStats("client_response.rcode", &cr_rcode, 0)
	o.writer.Write(b.Bytes())

	b = ReportStats("client_response.tc.src", &cr_tc_src, 60)
	o.writer.Write(b.Bytes())

	b = ReportStats("client_response.servfail.src", &cr_servfail_src, 60)
	o.writer.Write(b.Bytes())
	b = ReportStats("client_response.servfail.name", &cr_servfail_name, 60)
	o.writer.Write(b.Bytes())
	b = ReportStats("client_response.servfail.name_parent", &cr_servfail_name_p, 60)
	o.writer.Write(b.Bytes())

	b = ReportStats("client_response.nxdomain.src", &cr_nxdomain_src, 30)
	o.writer.Write(b.Bytes())
	b = ReportStats("client_response.nxdomain.name", &cr_nxdomain_name, 60)
	o.writer.Write(b.Bytes())
	b = ReportStats("client_response.nxdomain.name_p", &cr_nxdomain_name_p, 60)
	o.writer.Write(b.Bytes())

	b = ReportStats("client_response.slow.src", &cr_slow_src, 30)
	o.writer.Write(b.Bytes())
	b = ReportStats("client_response.slow.name", &cr_slow_name, 30)
	o.writer.Write(b.Bytes())
	b = ReportStats("client_response.slow.name_parent", &cr_slow_name_p, 30)
	o.writer.Write(b.Bytes())

	b = ReportStats("resolver_query.zone", &rq_zone, 120)
	o.writer.Write(b.Bytes())
	b = ReportStats("resolver_query.srv", &rq_srv, 120)
	o.writer.Write(b.Bytes())
	// b = ReportStats("resolver_query.name", &rq_name, 120)
	// o.writer.Write(b.Bytes())
	// b = ReportStats("resolver_query.name_parent", &rq_name_p, 120)
	// o.writer.Write(b.Bytes())

	b = ReportStats("resolver_response.slow.server", &rr_slow_srv, 3)
	o.writer.Write(b.Bytes())
	b = ReportStats("resolver_response.slow.name", &rr_slow_name, 3)
	o.writer.Write(b.Bytes())
	b = ReportStats("resolver_response.slow.name_parent", &rr_slow_name_p, 3)
	o.writer.Write(b.Bytes())
	b = ReportStats("resolver_response.slow.zone", &rr_slow_zone, 3)
	o.writer.Write(b.Bytes())

	o.writer.Flush()
	close(o.wait)
}

func (o *StatOutput) Close() {
	close(o.outputChannel)
	<-o.wait
	o.writer.Flush()
}

// EOF