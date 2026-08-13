define(["@grafana/data"], function (grafanaData) {
  function DataSource(instanceSettings) {
    this.url = instanceSettings.url;
  }
  DataSource.prototype.query = function () {
    return Promise.resolve({ data: [] });
  };
  DataSource.prototype.testDatasource = function () {
    return Promise.resolve({ status: "success", message: "ok" });
  };
  return { plugin: new grafanaData.DataSourcePlugin(DataSource) };
});
