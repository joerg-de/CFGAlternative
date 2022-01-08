/* ###
 * Copyright 2021-2022 joerg All Rights Reserved.
 * IP: GHIDRA
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
package cfgalternative.layout;

import cfgalternative.CFGNativeAdapter;
import ghidra.app.plugin.core.functiongraph.graph.SampleGraph;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.VisualGraphView;
import ghidra.graph.viewer.layout.AbstractVisualGraphLayout;
import ghidra.graph.viewer.layout.GridLocationMap;
import ghidra.graph.viewer.layout.LayoutPositions;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A custom layout to arrange the plugin vertices of the {@link SampleGraphPlugin}, using
 * the number of dependencies as a guide for arrangement.
 */
public class SampleGraphPluginDependencyLayout
    extends AbstractVisualGraphLayout<FGVertex, FGEdge> {

    VisualGraphView<FGVertex, FGEdge, SampleGraph> view;

    @Override
    protected GridLocationMap<FGVertex, FGEdge> performInitialGridLayout(
        VisualGraph<FGVertex, FGEdge> g) throws CancelledException {
        GridLocationMap<FGVertex, FGEdge> results = new GridLocationMap<>();
        return results;
    }
    public SampleGraphPluginDependencyLayout(SampleGraph graph, String name, VisualGraphView<FGVertex, FGEdge, SampleGraph> view) {
        super(graph, name);
        this.view = view;
    }

    @Override
    public SampleGraph getVisualGraph() {
        return (SampleGraph) getGraph();
    }

    @Override
    public AbstractVisualGraphLayout<FGVertex, FGEdge> createClonedLayout(
        VisualGraph<FGVertex, FGEdge> newGraph) {
        if (!(newGraph instanceof SampleGraph)) {
            throw new IllegalArgumentException("Must pass a " + SampleGraph.class.getSimpleName() +
                                               "to clone the " + getClass().getSimpleName());
        }

        SampleGraphPluginDependencyLayout newLayout =
            new SampleGraphPluginDependencyLayout((SampleGraph) newGraph, getLayoutName(), view);
        return newLayout;
    }


    //copy in DecompilerNestedLayoutProxy
    @Override
    public LayoutPositions<FGVertex, FGEdge> calculateLocations(VisualGraph<FGVertex, FGEdge> visualGraph,
            TaskMonitor taskMonitor) {
        return CFGNativeAdapter.calculateLocations(visualGraph,view,taskMonitor);
    }
}
