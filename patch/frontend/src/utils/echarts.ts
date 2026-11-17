import * as echarts from 'echarts/core';

import { LineChart, BarChart, PieChart, MapChart, EffectScatterChart } from 'echarts/charts';

import {
    TitleComponent,
    TooltipComponent,
    GridComponent,
    LegendComponent,
    VisualMapComponent,
    GeoComponent,
    PolarComponent,
    DataZoomComponent,
} from 'echarts/components';

import { CanvasRenderer, SVGRenderer } from 'echarts/renderers';

echarts.use([
    LineChart,
    BarChart,
    PieChart,
    MapChart,
    EffectScatterChart,

    TitleComponent,
    TooltipComponent,
    GridComponent,
    LegendComponent,
    VisualMapComponent,
    GeoComponent,
    PolarComponent,
    DataZoomComponent,

    CanvasRenderer,
    SVGRenderer,
]);

export default echarts;
