require([
  "splunkjs/mvc",
  "jquery",
  "splunkjs/mvc/simplexml/ready!"
], function(mvc, $) {

  // Hard-coded stanza string
  var scriptTitle = "$SPLUNK_HOME/etc/apps/ti_feeds_for_splunk/bin/fetch_feeds.py";

  function buildEndpoint() {
    return "/splunkd/__raw/servicesNS/nobody/ti_feeds_for_splunk/data/inputs/script/" +
           encodeURIComponent(scriptTitle) + "?output_mode=json";
  }

  // Inject HTML into the placeholder
  function renderUI() {
    var html = `
      <h3>Current Status</h3>
      <div id="status">Loading...</div>
      <h3>Update Settings</h3>
      <form>
        <label for="disabled">Disabled:</label>
        <select id="disabled">
          <option value="0">false (enabled)</option>
          <option value="1">true (disabled)</option>
        </select>
        <br><br>
        <label for="interval">Interval (seconds):</label>
        <input type="text" id="interval" value="3600"/>
        <br><br>
        <button type="button" id="apply" class="btn btn-primary">Apply Changes</button>
      </form>
      <div id="result" style="margin-top:10px;"></div>
    `;
    $("#feedControlContainer").html(html);
  }

  // Refresh status
  function refreshStatus() {
    $.get(Splunk.util.make_url(buildEndpoint()), function(data) {
      if (data && data.entry && data.entry[0]) {
        var c = data.entry[0].content;
        var table = `
          <table class="table table-striped table-bordered">
            <tr><th>Disabled</th><td>${c.disabled}</td></tr>
            <tr><th>Interval (sec)</th><td>${c.interval}</td></tr>
            <tr><th>Index</th><td>${c.index}</td></tr>
            <tr><th>Sourcetype</th><td>${c.sourcetype}</td></tr>
          </table>
        `;
        $("#status").html(table);

        // Pre-populate form
        $("#disabled").val(c.disabled ? "1" : "0");
        $("#interval").val(c.interval);
      } else {
        $("#status").text("⚠️ No content returned.");
      }
    }).fail(function(xhr) {
      $("#status").text("❌ Error fetching status: " + xhr.responseText);
    });
  }

  // Apply button handler
  function bindEvents() {
    $("#feedControlContainer").on("click", "#apply", function() {
      var disabled = $("#disabled").val();
      var interval = $("#interval").val();

      $.ajax({
        type: "POST",
        url: Splunk.util.make_url(buildEndpoint()),
        data: { disabled: disabled, interval: interval },
        success: function() {
          $("#result").text("✅ Updated successfully!");
          refreshStatus();
        },
        error: function(xhr) {
          $("#result").text("❌ Error: " + xhr.responseText);
        }
      });
    });
  }

  // Initialize
  renderUI();
  bindEvents();
  refreshStatus();
});
