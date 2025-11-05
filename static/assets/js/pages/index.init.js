/**
 * Theme: Approx - Bootstrap 5 Responsive Admin Dashboard
 * Author: Mannatthemes
 * Analytics Dashboard Js
 */

// apex-bar-1

var options = {
  chart: {
      height: 400,
      type: 'bar',
      toolbar: {
          show: false
      },
  },
  plotOptions: {
      bar: {
          horizontal: true,
      }
  },
  dataLabels: {
      enabled: false
  },
  series: [{
      data: [100, 60, 25, 15]
  }],
  colors: ["var(--bs-primary)"],
  yaxis: {
      axisBorder: {
          show: true,
          color: '#bec7e0',
        },  
        axisTicks: {
          show: true,
          color: '#bec7e0',
      }, 
  },
  xaxis: {
      categories: ['Total', 'Completed', 'Pending', 'Expired'],        
  },
  states: {
      hover: {
          filter: 'none'
      }
  },
  grid: {
      borderColor: '#f1f3fa'
  }
}

var chart = new ApexCharts(
  document.querySelector("#apex_bar_simple"),
  options
);

chart.render();


  
   //customers-widget
  
   
   var options = {
    chart: {
        height: 320,
        type: 'donut',
    }, 
    plotOptions: {
      pie: {
        donut: {
          size: '80%'
        }
      }
    },
    dataLabels: {
      enabled: false,
    },
  
    stroke: {
      show: true,
      width: 2,
      colors: ['transparent']
    },
   
    series: [45, 35, 20],
    legend: {
      show: true,
      position: 'bottom',
      horizontalAlign: 'center',
      verticalAlign: 'middle',
      floating: false,
      fontSize: '13px',
      fontFamily: "Be Vietnam Pro, sans-serif",
      offsetX: 0,
      offsetY: 0,
    },
    labels: [ "Typed","Drawn", "Uploaded" ],
    colors: ["#0e2a89", "#d96345", "#ffb600" ],
   
    responsive: [{
        breakpoint: 600,
        options: {
          plotOptions: {
              donut: {
                customScale: 0.2
              }
            },        
            chart: {
                height: 240
            },
            legend: {
                show: false
            },
        }
    }],
    tooltip: {
      y: {
          formatter: function (val) {
              return   val + " %"
          }
      }
    }
    
  }
  
  var chart = new ApexCharts(
    document.querySelector("#balance"),
    options
  );
  
  chart.render();