/* ###
 * Copyright 2021-2022 joerg All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cfgalternative;

import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.SampleGraph;
import ghidra.app.plugin.core.functiongraph.graph.layout.DecompilerNestedLayout;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.VisualGraphView;
import ghidra.graph.viewer.layout.LayoutPositions;
import ghidra.util.task.TaskMonitor;

public class DecompilerNestedLayoutProxy extends DecompilerNestedLayout {


    VisualGraphView<FGVertex, FGEdge, SampleGraph> view;

    public DecompilerNestedLayoutProxy(FunctionGraph graph, String name) {
        super(graph, name);
    }
    public void setView(VisualGraphView<FGVertex, FGEdge, SampleGraph> view)
    {
        this.view = view;
    }
    //copy in SampleGraphPluginDependencyLayout
    @Override
    public LayoutPositions<FGVertex, FGEdge> calculateLocations(VisualGraph<FGVertex, FGEdge> visualGraph,
            TaskMonitor taskMonitor) {
        return CFGNativeAdapter.calculateLocations(visualGraph,view,taskMonitor);
    }

}
