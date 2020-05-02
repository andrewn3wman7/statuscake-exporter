package collector

import (
	"strings"
	"github.com/andrewn3wman7/statuscake-exporter/stk"
	"github.com/prometheus/client_golang/prometheus"
)

type stkPagespeedCollector struct {
	stkPagespeedLoadTime     *prometheus.Desc
	stkPagespeedNbRequests   *prometheus.Desc
	stkPagespeedFilesize     *prometheus.Desc
	StkAPI        *stk.StkAPI
}

const (
	stkPagespeedCollectorSubsystem = "pagespeed"
)

func init() {
	registerCollector("pagespeed", defaultEnabled, NewStkPagespeedCollector)
}

//NewStkPagespeedCollector is a Status Cake Pagespeed Collector
func NewStkPagespeedCollector() (Collector, error) {
	return &stkPagespeedCollector{
		stkPagespeedLoadTime: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, stkPagespeedCollectorSubsystem, "load_time"),
			"StatusCake Pagespeed Load time (in ms)",
			[]string{"name","website_url","Location","contactGroupId"}, nil,
		),
		stkPagespeedNbRequests: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, stkPagespeedCollectorSubsystem, "nb_requests"),
			"StatusCake Pagespeed Nb of Requests",
			[]string{"name","website_url","Location","contactGroupId"}, nil,
		),
		stkPagespeedFilesize: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, stkPagespeedCollectorSubsystem, "filesize"),
			"StatusCake Pagespeed Filesize (in kb)",
			[]string{"name","website_url","Location","contactGroupId"}, nil,
		),
	}, nil
}

// Update implements Collector and exposes related metrics
func (c *stkPagespeedCollector) Update(ch chan<- prometheus.Metric) error {
	if err := c.updateStkPagespeed(ch); err != nil {
		return err
	}
	return nil
}

func (c *stkPagespeedCollector) UpdateConfig(stkAPI *stk.StkAPI) error {
	c.StkAPI = stkAPI
	return nil
}

func (c *stkPagespeedCollector) updateStkPagespeed(ch chan<- prometheus.Metric) error {

	if c.StkAPI == nil {
		return nil
	}
	tests := c.StkAPI.GetTestsPageSpeed()
	if len(tests.Data) < 1 {
		return nil
	}

	for _, t := range tests.Data {

		ch <- prometheus.MustNewConstMetric(
			c.stkPagespeedLoadTime,
			prometheus.GaugeValue,
			float64(t.LatestStats.LoadtimeMs),
			t.Title,
			t.URL,
			t.LocationISO,
			strings.Join(t.ContactGroups[:],","),
		)

		ch <- prometheus.MustNewConstMetric(
			c.stkPagespeedNbRequests,
			prometheus.GaugeValue,
			float64(t.LatestStats.Requests),
			t.Title,
			t.URL,
			t.LocationISO,
			strings.Join(t.ContactGroups[:],","),
		)

		ch <- prometheus.MustNewConstMetric(
			c.stkPagespeedFilesize,
			prometheus.GaugeValue,
			float64(t.LatestStats.FilesizeKb),
			t.Title,
			t.URL,
			t.LocationISO,
			strings.Join(t.ContactGroups[:],","),
		)
	}

	return nil
}
