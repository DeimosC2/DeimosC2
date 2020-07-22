/* eslint-disable */
export const optionsColumn = {
  chart: {
    type: 'bar',
    animations: {
      enabled: true,
      easing: 'linear',
      dynamicAnimation: {
        speed: 1000,
      }
    },
    // dropShadow: {
    //   enabled: true,
    //   left: -14,
    //   top: -10,
    //   opacity: 0.05
    // },
    // events: {
    //   animationEnd: function (chartCtx) {
    //     const newData = chartCtx.w.config.series[0].data.slice()
    //     newData.shift()
    //     window.setTimeout(function () {
    //       chartCtx.updateOptions({
    //         series: [{
    //           data: newData,
    //         }],
    //         xaxis: {
    //           min: chartCtx.minX,
    //           max: chartCtx.maxX,
    //         },
    //         subtitle: {
    //           // text: parseInt(getRangeRandom({ min: 1, max: 20 })).toString() + '%',
    //         }
    //       }, false, false)
    //     }, 300)
    //   }
    // },
    toolbar: {
      show: true,
    },
    zoom: {
      enabled: false,
    }
  },
  dataLabels: {
    enabled: false,
  },
  stroke: {
    width: 0,
  },
  fill: {
    type: 'gradient',
    gradient: {
      shade: 'dark',
      type: 'vertical',
      shadeIntensity: 0.5,
      inverseColors: false,
      opacityFrom: 1,
      opacityTo: 0.8,
      stops: [0, 100],
    }
  },
  // xaxis: {
  //   type: 'datetime',
  //   range: 2700000,
  // },
  legend: {
    show: true
  },
};

export const optionsLine = {
  chart: {
    animations: {
      enabled: true,
      easing: 'easeinout',
      dynamicAnimation: {
        speed: 1000,
      }
    },
    // dropShadow: {
    //   enabled: true,
    //   opacity: 0.3,
    //   blur: 5,
    //   left: -7,
    //   top: 22,
    // },
    toolbar: {
      show: true,
      tools: {
        pan: false,
      },
    },
    zoom: {
      enabled: true,
    }
  },
  dataLabels: {
    enabled: false,
  },
  grid: {
    padding: {
      left: 0,
      right: 0,
    }
  },
  markers: {
    size: 0,
    hover: {
      size: 0,
    }
  },
};

export const optionsCircle = {
  chart: {
    type: 'donut',
    // height: 320,
    offsetY: 0,
    offsetX: 30,
  },
  plotOptions: {
    radialBar: {
      inverseOrder: false,
      hollow: {
        margin: 5,
        size: '10%',
        background: 'transparent',
      },
      track: {
        show: true,
        background: '#40475D',
        strokeWidth: '100%',
        opacity: 1,
        margin: 3, // margin is in pixels
      },
    },
  },
  fill: {
    type: 'gradient',
    gradient: {
      shade: 'dark',
      type: 'horizontal',
      shadeIntensity: 0.5,
      inverseColors: true,
      opacityFrom: 1,
      opacityTo: 1,
      stops: [0, 100],
    }
  }
};

export const optionsProgress1 = {
  chart: {
    height: 70,
    type: 'bar',
    stacked: true,
    sparkline: {
      enabled: true,
    }
  },
  plotOptions: {
    bar: {
      horizontal: true,
      barHeight: '20%',
      colors: {
        backgroundBarColors: ['#40475D'],
      }
    },
  },
  stroke: {
    width: 0,
  },
  series: [{
    name: 'Process 1',
    data: [44]
  }],
  title: {
    floating: true,
    offsetX: -10,
    offsetY: 5,
    text: 'Process 1'
  },
  subtitle: {
    floating: true,
    align: 'right',
    offsetY: 0,
    text: '44%',
    style: {
      fontSize: '20px',
    }
  },
  tooltip: {
    enabled: false
  },
  xaxis: {
    categories: ['Process 1'],
  },
  yaxis: {
    max: 100
  },
  fill: {
    opacity: 1
  }
};

export const optionsProgress2 = {
  chart: {
    height: 70,
    type: 'bar',
    stacked: true,
    sparkline: {
      enabled: true,
    }
  },
  plotOptions: {
    bar: {
      horizontal: true,
      barHeight: '20%',
      colors: {
        backgroundBarColors: ['#40475D'],
      }
    },
  },
  colors: ['#17ead9'],
  stroke: {
    width: 0,
  },
  series: [{
    name: 'Process 2',
    data: [80],
  }],
  title: {
    floating: true,
    offsetX: -10,
    offsetY: 5,
    text: 'Process 2',
  },
  subtitle: {
    floating: true,
    align: 'right',
    offsetY: 0,
    text: '80%',
    style: {
      fontSize: '20px',
    }
  },
  tooltip: {
    enabled: false,
  },
  xaxis: {
    categories: ['Process 2'],
  },
  yaxis: {
    max: 100,
  },
  fill: {
    type: 'gradient',
    gradient: {
      inverseColors: false,
      gradientToColors: ['#6078ea'],
    }
  },
};

export const optionsProgress3 = {
  chart: {
    height: 70,
    type: 'bar',
    stacked: true,
    sparkline: {
      enabled: true,
    }
  },
  plotOptions: {
    bar: {
      horizontal: true,
      barHeight: '20%',
      colors: {
        backgroundBarColors: ['#40475D'],
      }
    },
  },
  colors: ['#f02fc2'],
  stroke: {
    width: 0,
  },
  series: [{
    name: 'Process 3',
    data: [74],
  }],
  fill: {
    type: 'gradient',
    gradient: {
      gradientToColors: ['#6094ea'],
    }
  },
  title: {
    floating: true,
    offsetX: -10,
    offsetY: 5,
    text: 'Process 3'
  },
  subtitle: {
    floating: true,
    align: 'right',
    offsetY: 0,
    text: '74%',
    style: {
      fontSize: '20px',
    }
  },
  tooltip: {
    enabled: false,
  },
  xaxis: {
    categories: ['Process 3'],
  },
  yaxis: {
    max: 100,
  },
};

// export default {
//   optionsColumn,
//   optionsLine,
//   optionsCircle,
//   optionsProgress1,
//   optionsProgress2,
//   optionsProgress3,
// }
