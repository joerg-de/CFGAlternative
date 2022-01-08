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

import javax.swing.Icon;

import ghidra.app.plugin.core.functiongraph.graph.SampleGraph;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.VisualGraphView;
import ghidra.graph.viewer.layout.AbstractLayoutProvider;
import ghidra.graph.viewer.layout.LayoutPositions;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;


/**
 * A layout provider for the {@link SampleGraphPlugin}
 */
public class SampleGraphPluginDependencyLayoutProvider
    extends AbstractLayoutProvider<FGVertex, FGEdge, SampleGraph> {

    private static final String NAME = "Nested Code Layout"; //this needs to be that name to get access to the options from the normal CFG
    private static final Icon DEFAULT_ICON = ResourceManager.loadImage("images/color_swatch.png");

    private VisualGraphView<FGVertex, FGEdge, SampleGraph> view;

    public SampleGraphPluginDependencyLayoutProvider(VisualGraphView<FGVertex, FGEdge, SampleGraph> view)
    {
        this.view = view;
    }

    @Override
    public VisualGraphLayout<FGVertex, FGEdge> getLayout(SampleGraph g, TaskMonitor monitor)
    throws CancelledException {

        SampleGraphPluginDependencyLayout layout = new SampleGraphPluginDependencyLayout(g, NAME, view);
        initVertexLocations(g, layout);


        return layout;
    }
    public LayoutPositions<FGVertex, FGEdge> calculateLocations(VisualGraph<FGVertex,FGEdge> g, TaskMonitor monitor)
    {
        SampleGraphPluginDependencyLayout layout = new SampleGraphPluginDependencyLayout((SampleGraph)(g), NAME, view);
        return layout.calculateLocations(g, monitor);
    }

    @Override
    public String getLayoutName() {
        return NAME;
    }

    // Note: each provider really should load its own icon so that the toolbar item can
    //       signal to the user which layout is active
    @Override
    public Icon getActionIcon() {
        return DEFAULT_ICON;
    }
}
