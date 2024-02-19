package cfx_vrops

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	internalMetric "github.com/influxdata/telegraf/metric"
	"github.com/influxdata/telegraf/plugins/common/proxy"
	"github.com/influxdata/telegraf/plugins/common/tls"
	"github.com/influxdata/telegraf/plugins/inputs"
)

// VROpsClient struct to hold client details
type VROpsClient struct {
	Hostname           string          `toml:"hostname"`
	Username           string          `toml:"username"`
	Password           config.Secret   `toml:"password"`
	Scheme             string          `toml:"scheme"`
	Timeout            config.Duration `toml:"timeout"`
	Period             config.Duration `toml:"period"`
	Delay              config.Duration `toml:"delay"`
	IntervalQuantifier int64           `toml:"interval_quantifier"`
	IntervalType       string          `toml:"interval_type"`
	RollUpType         string          `toml:"rollup_type"`
	Metric             []string        `toml:"metric"`
	BatchSize          int64           `toml:"batch_size"`
	ResourceKind       string          `toml:"resource_kind"`
	AdapterKind        string          `toml:"adapter_kind"`
	Log                telegraf.Logger `toml:"-"`
	Token              string
	Headers            http.Header
	windowStart        int64
	windowEnd          int64

	tls.ClientConfig
	proxy.HTTPProxy
}

var sampleConfig string

func (*VROpsClient) SampleConfig() string {
	return sampleConfig
}

func (c *VROpsClient) updateWindow(relativeTo time.Time) {
	windowEnd := relativeTo.Add(-time.Duration(c.Delay))
	// fmt.Println(period, relativeTo, delay, windowEnd)

	if c.windowEnd == 0 {
		// this is the first run, no window info, so just get a single period
		c.windowStart = windowEnd.Add(-time.Duration(c.Period)).UnixMilli()
	} else {
		// subsequent window, start where last window left off
		c.windowStart = c.windowEnd
	}

	c.windowEnd = windowEnd.UnixMilli()
}

func (client *VROpsClient) PrepareHTTPClient() (*http.Client, error) {
	proxyFunc, err := client.Proxy()
	if err != nil {
		return nil, err
	}

	tls_config, err := client.TLSConfig()
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		TLSClientConfig: tls_config,
		Proxy:           proxyFunc,
	}

	http_client := http.Client{Transport: tr, Timeout: time.Duration(client.Timeout)}

	return &http_client, nil
}

func (client *VROpsClient) PrepareRequest(method string, url string, payloadBytes []byte, Headers http.Header) (*http.Request, error) {
	req, error_ := http.NewRequest(method, url, bytes.NewBuffer(payloadBytes))
	if error_ != nil {
		return nil, error_
	}
	req.Header = Headers

	return req, nil
}

// InitToken initializes the client token
func (client *VROpsClient) InitToken() error {
	if client.Token != "" {
		return nil
	}
	password, err := client.Password.Get()

	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s://%s/suite-api/api/auth/token/acquire", client.Scheme, client.Hostname)
	payload := map[string]string{
		"username":   client.Username,
		"authSource": "local",
		"password":   password.String(),
	}
	payloadBytes, _ := json.Marshal(payload)

	http_client, err := client.PrepareHTTPClient()
	if err != nil {
		return err
	}

	headers := http.Header{
		"Accept":       []string{"application/json"},
		"Content-Type": []string{"application/json"},
	}

	req, err := client.PrepareRequest("POST", url, payloadBytes, headers)
	if err != nil {
		return err
	}

	resp, err := http_client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to acquire token, status: %s, body: %s", resp.Status, string(body))
	}

	var responseJson struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&responseJson); err != nil {
		return err
	}

	client.Token = "vRealizeOpsToken " + responseJson.Token
	client.Headers = http.Header{
		"Authorization": []string{client.Token},
		"Accept":        []string{"application/json"},
		"Content-Type":  []string{"application/json"},
	}
	return nil
}

func (client *VROpsClient) GetResourcesSummary(maxRows, pageSize int) ([]interface{}, error) {
	client.Log.Info("Starting collection for resources...")
	type PageInfo struct {
		TotalCount int `json:"totalCount"`
	}

	type ResourceListResponse struct {
		ResourceList []map[string]interface{} `json:"resourceList"`
		PageInfo     PageInfo                 `json:"pageInfo"`
	}

	req_url := fmt.Sprintf("%s://%s/suite-api/api/resources/", client.Scheme, client.Hostname)
	page := 0

	if maxRows > 0 && maxRows < pageSize {
		pageSize = maxRows
	}

	var resourceSummaries []interface{}
	count := 0

	for {
		queryParams := url.Values{}
		queryParams.Set("page", fmt.Sprintf("%d", page))
		queryParams.Set("pageSize", fmt.Sprintf("%d", pageSize))

		fmt.Println(client.ResourceKind)
		if client.ResourceKind != "" {
			queryParams.Set("ResourceKind", client.ResourceKind)
		}

		if client.AdapterKind != "" {
			queryParams.Set("AdapterKind", client.AdapterKind)
		}

		requestUrl := fmt.Sprintf("%s?%s", req_url, queryParams.Encode())

		http_client, err := client.PrepareHTTPClient()
		if err != nil {
			return nil, err
		}

		req, err := client.PrepareRequest("GET", requestUrl, nil, client.Headers)
		if err != nil {
			return nil, err
		}

		req.Header = client.Headers

		resp, err := http_client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("received non-OK response status: %s", resp.Status)
		}

		responseBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var response ResourceListResponse

		if err := json.Unmarshal(responseBody, &response); err != nil {
			return nil, err
		}

		for _, item := range response.ResourceList {
			jsonData := map[string]interface{}{
				"identifier":            item["identifier"],
				"name":                  item["resourceKey"].(map[string]interface{})["name"],
				"resource_kind":         item["resourceKey"].(map[string]interface{})["resourceKindKey"],
				"creation_time":         item["creationTime"],
				"resource_health":       item["resourceHealth"],
				"resource_health_value": item["resourceHealthValue"],
			}

			resourceSummaries = append(resourceSummaries, jsonData)
			if maxRows > 0 && len(resourceSummaries) >= maxRows {
				return resourceSummaries, nil
			}
		}

		count += len(response.ResourceList)
		client.Log.Infof("Collected resources: %v. Total Count: %v", count, response.PageInfo.TotalCount)
		if count >= response.PageInfo.TotalCount {
			break
		}
		page++
	}

	return resourceSummaries, nil
}

// GetVMMetric fetches VM metrics - Simplified version
func (client *VROpsClient) GetVMMetric(resourceID []string) ([]interface{}, error) {

	url := fmt.Sprintf("%s://%s/suite-api/api/resources/stats/query", client.Scheme, client.Hostname)
	payload := MetricQueryPayload{
		Begin:              client.windowStart,
		End:                client.windowEnd,
		ResourceID:         resourceID,
		StatKey:            client.Metric,
		IntervalQuantifier: int(client.IntervalQuantifier),
		IntervalType:       client.IntervalType,
		RollUpType:         client.RollUpType,
	}
	payloadBytes, _ := json.Marshal(payload)

	http_client, err := client.PrepareHTTPClient()
	if err != nil {
		return nil, err
	}

	req, err := client.PrepareRequest("POST", url, payloadBytes, client.Headers)
	if err != nil {
		return nil, err
	}

	resp, err := http_client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get VM metrics, status: %s, body: %s", resp.Status, string(body))
	}

	var responseJson struct {
		Values []interface{} `json:"values"`
	}

	// body, err := io.ReadAll(resp.Body)

	err = json.NewDecoder(resp.Body).Decode(&responseJson)
	if err != nil {
		return nil, err
	}

	// fmt.Println("raw response=============", responseJson.Values)
	return responseJson.Values, nil
}

type MetricQueryPayload struct {
	Begin              int64    `json:"begin"`
	End                int64    `json:"end"`
	IntervalQuantifier int      `json:"intervalQuantifier"`
	IntervalType       string   `json:"intervalType"`
	RollUpType         string   `json:"rollUpType"`
	ResourceID         []string `json:"resourceId"`
	StatKey            []string `json:"statKey"`
}

func millisecondsToTime(milliseconds float64) time.Time {
	seconds := int64(milliseconds / 1000)
	nanoseconds := int64((milliseconds - float64(seconds*1000)) * 1e6)
	return time.Unix(seconds, nanoseconds)
}

func createBatches(input []interface{}, batchSize int) []interface{} {
	var batches []interface{}

	for i := 0; i < len(input); i += batchSize {
		end := i + batchSize
		if end > len(input) {
			end = len(input)
		}

		batch := input[i:end]

		var resources_batch []string
		for _, i := range batch {
			resources_batch = append(resources_batch, i.(map[string]interface{})["identifier"].(string))
		}
		batches = append(batches, resources_batch)
	}

	return batches
}

func (client *VROpsClient) Gather(acc telegraf.Accumulator) error {
	// resourceId := "073eaaf7-7421-4744-ae32-39338e468a80"
	client.Log.Info("Plugin called")
	client.Log.Info(os.Environ())
	if err := client.InitToken(); err != nil {
		return err
	}
	resourceSummaries, summary_err := client.GetResourcesSummary(0, 1000)

	grouper := internalMetric.NewSeriesGrouper()

	if summary_err != nil {
		return summary_err
	}

	client.updateWindow(time.Now())
	client.Log.Infof("Window start: %v, window end: %v", client.windowStart, client.windowEnd)

	batchedSummaries := createBatches(resourceSummaries, int(client.BatchSize))
	client.Log.Infof("Number of batches: %v", len(batchedSummaries))
	client.Log.Info("Starting collection for Metrics...")
	for _, resource := range batchedSummaries {
		// resourceId := resource.(map[string]interface{})["identifier"].(string)

		result, err := client.GetVMMetric(resource.([]string))
		if err != nil {
			acc.AddError(err)
			return err
		}
		// fmt.Println(result)

		for _, record := range result {
			for _, stat := range record.(map[string]interface{})["stat-list"].(map[string]interface{})["stat"].([]interface{}) {
				data := stat.(map[string]interface{})["data"].([]interface{})
				timestamps := stat.(map[string]interface{})["timestamps"].([]interface{})
				statKey := stat.(map[string]interface{})["statKey"]
				resourceId := record.(map[string]interface{})["resourceId"].(string)

				tags := map[string]string{
					"intervalUnit_quantifier":   strconv.FormatFloat(stat.(map[string]interface{})["intervalUnit"].(map[string]interface{})["quantifier"].(float64), 'f', -1, 64),
					"intervalUnit_intervalType": stat.(map[string]interface{})["intervalUnit"].(map[string]interface{})["intervalType"].(string),
					"rollUpType":                stat.(map[string]interface{})["rollUpType"].(string),
					"statKey":                   statKey.(map[string]interface{})["key"].(string),
					"resourceId":                resourceId,
				}

				for i, d := range data {
					grouper.Add(resourceId, tags, millisecondsToTime(timestamps[i].(float64)), statKey.(map[string]interface{})["key"].(string), d)
				}
			}
		}

		for _, metric := range grouper.Metrics() {
			acc.AddMetric(metric)
		}
	}

	client.Log.Info("Metric Collection completed, returning.")
	return nil
}

func init() {
	inputs.Add("vrops", func() telegraf.Input {
		return &VROpsClient{
			Scheme:             "https",
			Timeout:            config.Duration(60 * time.Second),
			Period:             config.Duration(5 * time.Minute),
			Delay:              config.Duration(30 * time.Second),
			IntervalQuantifier: 1,
			IntervalType:       "MINUTES",
			RollUpType:         "AVG",
			BatchSize:          100,
		}
	})
}

// // NewVROpsClient creates a new VROps client
// func NewVROpsClient(hostname, username, password string) *VROpsClient {
// 	return &VROpsClient{
// 		Hostname:           hostname,
// 		Username:           username,
// 		Password:           password,
// 		Scheme:             "https",
// 		Timeout:            config.Duration(60 * time.Second),
// 		Period:             config.Duration(20 * time.Minute),
// 		Delay:              config.Duration(30 * time.Second),
// 		IntervalQuantifier: 1,
// 		IntervalType:       "MINUTES",
// 		RollUpType:         "AVG",
// 		Metric:             []string{"cpu|usagemhz_average", "disk|usage_average"},
// 		batchSize:          100,
// 		ResourceKind:       "VirtualMachine",
// 	}
// }
// func main() {
// 	creds := VROpsClient{
// 		Hostname: "10.95.159.64",
// 		Username: "admin",
// 		Password: "Abcd123$",
// 	}

// 	client := NewVROpsClient(creds.Hostname, creds.Username, creds.Password)

// 	// Example usage of GetVMMetric
// 	// data, err := client.GetVMMetric("073eaaf7-7421-4744-ae32-39338e468a80")
// 	// if err != nil {
// 	// 	fmt.Println("Error fetching VM metrics:", err)
// 	// 	return
// 	// }
// 	// fmt.Println(data)

// 	// resp, error := client.GetResourcesSummary("", "", 0, 1000)
// 	// if error != nil {
// 	// 	fmt.Println("Error fetching VM Resources:", error)
// 	// 	return
// 	// }
// 	// fmt.Println(resp)

// 	var acc testutil.Accumulator
// 	err := client.Gather(&acc)
// 	if err != nil {
// 		fmt.Println("Error fetching VM metrics:", err)
// 		return
// 	}
// 	fmt.Println(&acc)
// }
