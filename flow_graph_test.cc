// Copyright 2011-2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "third_party/zynamics/bindiff/flow_graph.h"

#include "gtest/gtest.h"
#include "third_party/zynamics/bindiff/config.h"
#include "third_party/zynamics/bindiff/test_util.h"

namespace security::bindiff {
namespace {

class FlowGraphLimitsTest : public ::testing::Test {
 protected:
  void SetUp() override { saved_ = config::Proto(); }
  void TearDown() override { config::Proto() = saved_; }

  void Configure(const std::string& json) {
    auto loaded = config::LoadFromJson(json);
    ASSERT_TRUE(loaded.ok()) << loaded.status();
    config::Proto() = *loaded;
  }

  void ExpectBody(int instructions, int blocks, int expected_blocks) {
    BinExport2 proto;
    proto.add_mnemonic()->set_name("nop");
    proto.mutable_call_graph()->add_vertex()->set_address(0x1000);
    auto* graph = proto.add_flow_graph();
    graph->set_entry_basic_block_index(0);
    for (int i = 0; i < instructions; ++i) {
      auto* instruction = proto.add_instruction();
      instruction->set_address(0x1000 + i);
      instruction->set_raw_bytes("\x90");
      instruction->set_mnemonic_index(0);
    }
    for (int i = 0; i < blocks; ++i) {
      auto* range = proto.add_basic_block()->add_instruction_index();
      range->set_begin_index(i);
      range->set_end_index(i == blocks - 1 ? instructions : i + 1);
      graph->add_basic_block_index(i);
      if (i > 0) {
        auto* edge = graph->add_edge();
        edge->set_source_basic_block_index(i - 1);
        edge->set_target_basic_block_index(i);
        edge->set_type(BinExport2::FlowGraph::Edge::UNCONDITIONAL);
      }
    }
    CallGraph call_graph;
    ASSERT_TRUE(call_graph.Read(proto, "limits.BinExport").ok());
    Instruction::Cache cache;
    auto loaded = FlowGraph::FromProto(proto, *graph, call_graph, cache);
    ASSERT_TRUE(loaded.ok()) << loaded.status();
    EXPECT_EQ(expected_blocks, (*loaded)->GetBasicBlockCount());
    if (expected_blocks) {
      EXPECT_EQ(instructions, (*loaded)->GetInstructionCount());
    }
  }

 private:
  Config saved_;
};

TEST_F(FlowGraphLimitsTest, DefaultsAndRaisedInstructionLimit) {
  Configure("{}");
  ExpectBody(9999, 1, 1);
  ExpectBody(10000, 1, 0);
  ExpectBody(13003, 1, 0);
  Configure(R"({"flow_graph_limits":{"max_instructions":20000}})");
  ExpectBody(13003, 1, 1);
  ExpectBody(20000, 1, 0);
}

TEST_F(FlowGraphLimitsTest, BlockAndEdgeBoundaries) {
  Configure(R"({"flow_graph_limits":{"max_basic_blocks":3}})");
  ExpectBody(3, 2, 2);
  ExpectBody(3, 3, 0);
  Configure(R"({"flow_graph_limits":{"max_edges":2}})");
  ExpectBody(3, 2, 2);
  ExpectBody(3, 3, 0);
  Configure(R"({"flow_graph_limits":{"max_basic_blocks":4,"max_edges":3}})");
  ExpectBody(3, 3, 3);
}

TEST_F(FlowGraphLimitsTest, ZeroUsesDefaults) {
  Configure(R"({"flow_graph_limits":{"max_instructions":0}})");
  ExpectBody(9999, 1, 1);
  ExpectBody(10000, 1, 0);
}

TEST_F(FlowGraphLimitsTest, ExplicitZeroOverridesEarlierConfig) {
  Configure(R"({"flow_graph_limits":{"max_instructions":20000}})");
  auto user = config::LoadFromJson(
      R"({"flow_graph_limits":{"max_instructions":0}})");
  ASSERT_TRUE(user.ok()) << user.status();
  config::MergeInto(*user, config::Proto());
  ExpectBody(13003, 1, 0);
}

TEST(FlowGraphTest, FlowGraphDefaultValues) {
  FlowGraph flow_graph;
  EXPECT_EQ(0.0, flow_graph.GetMdIndex());
  EXPECT_EQ(0.0, flow_graph.GetMdIndexInverted());
  EXPECT_EQ(0, flow_graph.GetBasicBlockCount());
  EXPECT_EQ(0, flow_graph.GetLoopCount());
  EXPECT_EQ(0, flow_graph.GetEntryPointAddress());
  EXPECT_EQ(nullptr, flow_graph.GetFixedPoint());
  EXPECT_EQ(nullptr, flow_graph.GetCallGraph());

  flow_graph.CalculateCallLevels();
  flow_graph.CalculateTopology();

  // TODO(cblichmann): Test the following:
  //  void SetMdIndex(double index);
  //  void SetMdIndexInverted(double index);
  //  void SetFixedPoint(FixedPoint* fixed_point)
  //  void SetCallGraph(CallGraph* graph);
}

}  // namespace
}  // namespace security::bindiff
