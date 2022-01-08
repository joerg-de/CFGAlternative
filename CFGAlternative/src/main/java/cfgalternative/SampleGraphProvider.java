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

package cfgalternative;


import java.awt.BorderLayout;
import java.util.*;

import javax.swing.*;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.*;
import cfgalternative.layout.*;
import ghidra.app.plugin.core.functiongraph.graph.SampleGraph;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FGEdgeImpl;
import ghidra.app.plugin.core.functiongraph.graph.FGVertexType;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.ListingFunctionGraphVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.plugin.core.functiongraph.mvc.FGData;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphVertexAttributes;
import ghidra.framework.plugintool.*;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.layout.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import ghidra.app.plugin.core.functiongraph.FGProviderProxy;

/**
 * A {@link ComponentProvider} that is the UI component of the {@link SampleGraphPlugin}.  This
 * shows a graph of the plugins in the system.
 */
public class SampleGraphProvider extends ComponentProviderAdapter {

    /*package*/ static final String NAME = "Alternative Control Flow Graph";
    /*package*/ static final String SHOW_FILTER_ACTION_NAME = "Show Filter";
    /*package*/ static final String RELAYOUT_GRAPH_ACTION_NAME = "Relayout Graph";

    private static FlowPlugin plugin;
    private JPanel mainPanel;
    private JComponent component;
    
    private FGProviderProxy FGprovider = null;

    private SampleGraph graph;
    private VisualGraphView<FGVertex, FGEdge, SampleGraph> view;
    private LayoutProvider<FGVertex, FGEdge, SampleGraph> layoutProvider;

    private Function currentFunction;

    public SampleGraphProvider(PluginTool tool, FlowPlugin plugin,Function currentFunction) {
        super(tool, NAME, plugin.getName());
        SampleGraphProvider.plugin = plugin;
        this.currentFunction = currentFunction;

        addToTool();

        //swaped
        buildComponent();

        createActions();

        setHelpLocation(FlowPlugin.DEFAULT_HELP);
        
    }

    private void installGraph() {
        // needed to set new graph
        //if (graph != null) {
        //	graph.dispose();
        //}

        if (currentFunction != null)
        {
            buildGraph(currentFunction);

            view.setLayoutProvider(layoutProvider);
            view.setGraph(graph);
        }
    }

    void dispose() {
        removeFromTool();
    }

    @Override
    public void componentShown() {
        installGraph();
    }

    private void buildComponent() {

        view = new VisualGraphView<>();

        // these default to off; they are typically controlled via a UI element; the
        // values set here are arbitrary and are for demo purposes
        view.setVertexFocusPathHighlightMode(PathHighlightMode.OUT);
        view.setVertexHoverPathHighlightMode(PathHighlightMode.IN);

        component = view.getViewComponent();

        mainPanel = new JPanel(new BorderLayout());

        mainPanel.add(component, BorderLayout.CENTER);
    }


    //from FunctionGraphFactory
    private static Collection<FGEdge> getEdgesForStartVertex(
        BidiMap<CodeBlock, FGVertex> blockToVertexMap, FGVertex startVertex,
        FGController controller, TaskMonitor monitor) throws CancelledException {

        List<FGEdge> edges = new ArrayList<>();
        CodeBlock codeBlock = blockToVertexMap.getKey(startVertex);
        CodeBlockReferenceIterator destinations = codeBlock.getDestinations(monitor);
        for (; destinations.hasNext();) {
            CodeBlockReference reference = destinations.next();
            CodeBlock destinationBlock = reference.getDestinationBlock();
            FGVertex destinationVertex = blockToVertexMap.get(destinationBlock);
            if (destinationVertex == null) {
                continue;// no vertex means the code block is not in our function
            }

            edges.add(new FGEdgeImpl(startVertex, destinationVertex, reference.getFlowType(),
                                     controller.getFunctionGraphOptions()));
        }
        return edges;
    }
    private static boolean isEntry(CodeBlock codeBlock) {
        boolean isSource = true;
        try {
            CodeBlockReferenceIterator iter = codeBlock.getSources(TaskMonitor.DUMMY);
            while (iter.hasNext()) {
                isSource = false;
                if (iter.next().getFlowType().isCall()) {
                    // any calls into a code block will make it an 'entry'
                    return true;
                }
            }
        }
        catch (CancelledException e) {
            // will never happen, because I don't have a monitor
        }
        return isSource;
    }
    private static BidiMap<CodeBlock, FGVertex> createVertices(Function function,FGController controller, TaskMonitor monitor) throws CancelledException {

        BidiMap<CodeBlock, FGVertex> vertices = new DualHashBidiMap<>();
        CodeBlockModel blockModel = new BasicBlockModel(plugin.getCurrentProgram());

        AddressSetView addresses = function.getBody();
        CodeBlockIterator iterator = blockModel.getCodeBlocksContaining(addresses, monitor);
        monitor.initialize(addresses.getNumAddresses());

        for (; iterator.hasNext();) {
            CodeBlock codeBlock = iterator.next();

            FlowType flowType = codeBlock.getFlowType();
            boolean isEntry = isEntry(codeBlock);
            Address cbStart = codeBlock.getFirstStartAddress();
            if (cbStart.equals(function.getEntryPoint())) {
                isEntry = true;
            }

            FGVertex vertex =
                new ListingFunctionGraphVertex(controller, codeBlock, flowType, isEntry);

            //set Type
            if (vertex.isEntry()) {
                vertex.setVertexType(FGVertexType.ENTRY);
            }
            /*else if (vertex.isExit()) {
            	vertex.setVertexType(FGVertexType.EXIT);
            }*/
            else {
                vertex.setVertexType(FGVertexType.BODY);
            }

            vertices.put(codeBlock, vertex);

            long blockAddressCount = codeBlock.getNumAddresses();
            long currentProgress = monitor.getProgress();
            monitor.setProgress(currentProgress + blockAddressCount);
        }

        return vertices;
    }
    private static Collection<FGEdge> createdEdges(BidiMap<CodeBlock, FGVertex> vertices, FGController controller, TaskMonitor monitor) throws CancelledException {

        List<FGEdge> edges = new ArrayList<>();
        for (FGVertex startVertex : vertices.values()) {
            Collection<FGEdge> vertexEdges =
                getEdgesForStartVertex(vertices, startVertex, controller, monitor);

            edges.addAll(vertexEdges);
        }

        return edges;
    }
    //from FunctionGraphFactory end

    private void buildGraph(Function function) {
    	
    	if(FGprovider == null)
    	{
    		FGprovider = new FGProviderProxy(plugin,false);
    	}
    	
        TaskMonitor monitor = TaskMonitor.DUMMY;
        FGprovider.doSetProgram(plugin.getCurrentProgram());
        FGController controller = new FGController(FGprovider,plugin);
        FunctionGraphVertexAttributes settingsFG = new FunctionGraphVertexAttributes(plugin.getCurrentProgram());
        graph = new SampleGraph(function, settingsFG, Collections.emptySet(), Collections.emptySet());
        graph.setOptions(plugin.getFunctionGraphOptions());
        DecompilerNestedLayoutProxy templay = new DecompilerNestedLayoutProxy(graph,layoutProvider.getLayoutName());
        templay.setView(view);
        graph.setGraphLayout(templay);
        FGData FD = new FGData(function, graph);



        try {
            BidiMap<CodeBlock, FGVertex> vertices = createVertices(function, controller, monitor);
            Collection<FGEdge> edges;
            edges = createdEdges(vertices, controller, monitor);
            for (FGVertex vertex : vertices.values()) {
                graph.addVertex(vertex);
            }
            for (FGEdge e : edges) {
                graph.addEdge(e);
            }
        } catch (CancelledException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

        FGVertex functionEntryVertex = graph.getVertexForAddress(function.getEntryPoint());
        graph.setRootVertex(functionEntryVertex);
        graph.setOptions(controller.getFunctionGraphOptions());

        controller.setFunctionGraphData(FD);

        return;
    }

    /*package*/ SampleGraph getGraph() {
        return graph;
    }

    /*package*/ VisualGraphViewUpdater<?, ?> getGraphViewUpdater() {
        GraphViewer<FGVertex, FGEdge> viewer = view.getPrimaryGraphViewer();
        VisualGraphViewUpdater<FGVertex, FGEdge> updater = viewer.getViewUpdater();
        return updater;
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    private void createActions() {

        addLayoutAction();
    }

    private void addLayoutAction() {

        MultiStateDockingAction<LayoutProvider<FGVertex, FGEdge, SampleGraph>> layoutAction =
        new MultiStateDockingAction<>(RELAYOUT_GRAPH_ACTION_NAME, plugin.getName()) {

            @Override
            protected void doActionPerformed(ActionContext context) {
                // this callback is when the user clicks the button
                LayoutProvider<FGVertex, FGEdge, SampleGraph> currentUserData =
                    getCurrentUserData();
                changeLayout(currentUserData);
            }

            @Override
            public void actionStateChanged(
                ActionState<LayoutProvider<FGVertex, FGEdge, SampleGraph>> newActionState,
                EventTrigger trigger) {
                changeLayout(newActionState.getUserData());
            }
        };
        layoutAction.setGroup("B");
        layoutAction.setHelpLocation(FlowPlugin.DEFAULT_HELP);

        addLayoutProviders(layoutAction);

        addLocalAction(layoutAction);
    }

    private void changeLayout(LayoutProvider<FGVertex, FGEdge, SampleGraph> provider) {

        this.layoutProvider = provider;
        if (isVisible()) { // this can be called while building--ignore that
            installGraph();
        }
    }

    private void addLayoutProviders(
        MultiStateDockingAction<LayoutProvider<FGVertex, FGEdge, SampleGraph>> layoutAction) {

        // Note: the first state set will be made the current selected value of the multi action
        LayoutProvider<FGVertex, FGEdge, SampleGraph> provider =
            new SampleGraphPluginDependencyLayoutProvider(view);
        layoutAction.addActionState(
            new ActionState<>(provider.getLayoutName(), provider.getActionIcon(), provider));
    }

//==================================================================================================
// Inner Classes
//==================================================================================================


    public void setFunction(Function currentFunction) {
        this.currentFunction = currentFunction;

        if (currentFunction != null)
        {
            buildGraph(currentFunction);

            view.setLayoutProvider(layoutProvider);
            // set Locations

            SampleGraphPluginDependencyLayout s = new SampleGraphPluginDependencyLayout(graph,layoutProvider.getLayoutName(),view);
            //graph.setLayout(s);
            s.calculateLocations(graph, TaskMonitor.DUMMY);
            //
            view.setGraph(graph);
        }

    }
}
