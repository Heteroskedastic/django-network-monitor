AmCharts.checkEmptyData = function(chart) {
  if (0 == chart.dataProvider.length) {
    // set min/max on the value axis
    chart.valueAxes[0].minimum = 0;
    chart.valueAxes[0].maximum = 100;

    // add dummy data point
    var dataPoint = {
      dummyValue: 0
    };
    dataPoint[chart.categoryField] = '';
    chart.dataProvider = [dataPoint];

    // add label
    chart.addLabel(0, '50%', 'The chart contains no data', 'center', 15,
                   undefined, undefined, 0.5);
    chart.validateNow();
  }
};

function drawSerialChart(divId, config) {
  var graphCfg = {
      "bullet": "round",
      "lineThickness": 2,
      "bulletBorderAlpha": 1,
      "bulletSize": 1,
      "bulletColor": "#FFFFFF",
      "hideBulletsCount": 50,
      "useLineColorForBulletBorder": true,
  }, graphs = [];
  (config.graphs || []).forEach(function(g, i) {
    var newG = {};
    $.extend(true, newG, graphCfg);
    $.extend(true, newG, g);
    if (!newG.id) {
      newG.id = 'g'+(Math.round(Math.random() * 100000000));
    }
    graphs.push(newG);
  });
  config.graphs = graphs;
  var defaultGraph = config.graphs.length > 0 ? config.graphs[0].id: undefined;
  var defaults = {
      "type": "serial",
      "theme": "light",
      "titles": [],
      "marginRight": 50,
      "autoMarginOffset": 0,
      "marginTop": 7,
      "dataProvider": [],
      "legend":{
        "useGraphSettings": true,
        "fontSize": 13
      },
      "valueAxes": [{
          "axisAlpha": 0.07,
          "title": "value"
      }],
      "mouseWheelZoomEnabled": true,
      "graphs": [],
      "chartScrollbar": {
          "autoGridCount": true,
          "graph": defaultGraph,
          "scrollbarHeight": 40
      },
      "chartCursor": {
         "limitToGraph": defaultGraph,
         "categoryBalloonDateFormat": "JJ:NN, DD MMMM",
      },
      "categoryField": "timestamp",
      "categoryAxis": {
          "parseDates": true,
          "axisColor": "#DADADA",
          "minPeriod": "ss",
          "gridAlpha": 0.07
      },
      "export": {
          "enabled": true
      }
  };
  $.extend(true, defaults, config);
  if ((defaults.dataProvider || []).length == 0) {
    defaults.categoryAxis.parseDates = false;
  }
  var chart = AmCharts.makeChart(divId, defaults);
  AmCharts.checkEmptyData(chart);
  return chart
}
