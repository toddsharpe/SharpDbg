using System;
using System.Collections.Generic;
using System.ComponentModel.Design.Serialization;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace SharpDbg.Models
{
    class GraphGenerator
    {
        private static readonly HashSet<ud_mnemonic_code> ConditionalJumpCodes = new HashSet<ud_mnemonic_code>()
        {
            ud_mnemonic_code.UD_Ijnz,
            ud_mnemonic_code.UD_Ijz
        };

        private static readonly HashSet<ud_mnemonic_code> UnconditionalJumpCodes = new HashSet<ud_mnemonic_code>
        {
            ud_mnemonic_code.UD_Ijmp
        };

        private readonly List<Instruction> _instructions;
        private readonly int _entryIndex;
        private readonly uint _entryPoint;

        public List<BasicBlock> Functions { get; } = new List<BasicBlock>();

        public GraphGenerator(List<Instruction> instructions, uint entryPoint)
        {
            _entryPoint = entryPoint;
            _instructions = instructions;

            _entryIndex = GetInstructionIndex(_entryPoint);
        }

        private int GetInstructionIndex(uint address)
        {
            int i = 0;
            while (i < _instructions.Count)
            {
                if ((uint)_instructions[i].Offset == address)
                {
                    return i;
                }
                i++;
            }

            throw new Exception();
        }

        public void Generate()
        {
            Queue<uint> functionQueue = new Queue<uint>();
            functionQueue.Enqueue(_entryPoint);

            while (functionQueue.Count > 0)
            {
                uint startAddress = functionQueue.Dequeue();

                var block = GenerateFunction(startAddress, functionQueue);
                Functions.Add(block);
            }
        }

        //THis doesnt work because we never evaluate a true branch, so this needs to be a BFS not a flat search
        private BasicBlock GenerateFunction(uint startAddress, Queue<uint> functionQueue)
        {
            //Dictionary<uint, ControlFlow> flowGraph = MakeControlFlowGraph(startAddress);
            //Dictionary<uint, BasicBlock> blocks = MakeBasicBlocks(startAddress, flowGraph, functionQueue);

            //Walk linearly and record all branch targets
            Dictionary<uint, BasicBlock> blockHeaders = new Dictionary<uint, BasicBlock>
            {
                {startAddress, new BasicBlock {Address = startAddress}}
            };

            Queue<int> queue = new Queue<int>();
            queue.Enqueue(GetInstructionIndex(startAddress));

            while (queue.Count > 0)
            {
                int i = queue.Dequeue();
                while (_instructions[i].Mnemonic != ud_mnemonic_code.UD_Iret)
                {
                    Instruction current = _instructions[i];

                    if (current.Mnemonic == ud_mnemonic_code.UD_Icall)
                    {
                        uint address = (uint)((uint)current.Offset + current.Operands[0].LvalUDWord + current.Length);
                        functionQueue.Enqueue(address);
                    }
                    else if (ConditionalJumpCodes.Contains(current.Mnemonic))
                    {
                        //Signed values here don't work for backwards jumps, not sure how it works
                        uint address = (uint)((uint)current.Offset + current.Operands[0].LvalSByte + current.Length);

                        if (!blockHeaders.ContainsKey(address))
                        {
                            BasicBlock trueBlock = new BasicBlock { Address = address };
                            blockHeaders.Add(address, trueBlock);
                            queue.Enqueue(GetInstructionIndex(address));//Lets look at the true branch later
                        }

                        uint falseAddress = (uint) _instructions[i + 1].Offset;
                        if (!blockHeaders.ContainsKey(falseAddress))
                        {
                            BasicBlock falseBlock = new BasicBlock { Address = falseAddress };
                            blockHeaders.Add(falseAddress, falseBlock);
                        }
                    }
                    else if (UnconditionalJumpCodes.Contains(current.Mnemonic))
                    {
                        uint address = (uint)((uint)current.Offset + current.Operands[0].LvalUDWord + current.Length);
                        if (!blockHeaders.ContainsKey(address))
                        {
                            BasicBlock block = new BasicBlock { Address = address };
                            blockHeaders.Add(address, block);
                        }

                        i = GetInstructionIndex(address);
                        continue;
                    }

                    i++;
                }
            }

            //We have the block headers, time to make the graph
            var sorted = blockHeaders.Keys.OrderBy(i => i);


            return null;
        }
        
        //private Dictionary<uint, BasicBlock> MakeBasicBlocks(uint startAddress, Dictionary<uint, ControlFlow> flowGraph, Queue<uint> functionQueue)
        //{
        //    Dictionary<uint, BasicBlock> blocks = new Dictionary<uint, BasicBlock>();
        //    HashSet<uint> set = new HashSet<uint>();
        //    Queue<uint> blockQueue = new Queue<uint>();
        //    blockQueue.Enqueue(_instructions.Keys.Min());
        //    set.Add(blockQueue.Peek());

        //    while (blockQueue.Count > 0)
        //    {
        //        var address = blockQueue.Dequeue();
        //        BasicBlock block = new BasicBlock { Address = address };
        //        blocks.Add(address, block);

        //        while ((!flowGraph.ContainsKey(address)) || (flowGraph[address].Type == FlowType.None))
        //        {
        //            block.Instructions.Add(_instructions[address]);
        //            address += (uint)_instructions[address].Length;
        //        }

        //        //Take the jump
        //        block.Instructions.Add(_instructions[address]);

        //        //Enqueue the next ones
        //        var flow = flowGraph[address];
        //        if (flow.Type == FlowType.Unconditional)
        //        {

        //            if (!set.Contains(flow.UnconditionalLink))
        //                blockQueue.Enqueue(flow.UnconditionalLink);
        //        }

        //        else if (flow.Type == FlowType.Conditional)
        //        {
        //            if (!set.Contains(flow.TrueLink))
        //                blockQueue.Enqueue(flow.TrueLink);
        //            if (!set.Contains(flow.FalseLink))
        //                blockQueue.Enqueue(flow.FalseLink);
        //        }

        //        block.Size = block.Instructions.Select(i => i.Length).Aggregate((a, b) => a + b);
        //    }

        //    return blocks;
        //} 

        //private Dictionary<uint, ControlFlow> MakeControlFlowGraph(uint startAddress)
        //{
        //    Dictionary<uint, ControlFlow> flowGraph = new Dictionary<uint, ControlFlow>();

        //    HashSet<uint> set = new HashSet<uint>();
        //    Queue<uint> queue = new Queue<uint>();
        //    queue.Enqueue(startAddress);

        //    while (queue.Count > 0)
        //    {
        //        var address = queue.Dequeue();

        //        if (flowGraph.ContainsKey(address))
        //            continue;

        //        var instruction = _instructions[address];
        //        while (instruction.Mnemonic != ud_mnemonic_code.UD_Iret)
        //        {
        //            ControlFlow flow = new ControlFlow();
        //            if ((ConditionalJumpCodes.Contains(instruction.Mnemonic)))
        //            {
        //                string destination = instruction.ToString().Split(' ')[1];
        //                uint i = uint.Parse(destination.Substring(2), NumberStyles.HexNumber);

        //                flow.Type = FlowType.Conditional;
        //                flow.TrueLink = i;
        //                if (!set.Contains(i))
        //                {
        //                    queue.Enqueue(i);
        //                    set.Add(i);
        //                }
        //                flow.FalseLink = address + (uint)instruction.Length;

        //                if (!set.Contains(address + (uint)instruction.Length))
        //                {
        //                    queue.Enqueue(address + (uint)instruction.Length);
        //                    set.Add(address + (uint)instruction.Length);
        //                }

        //                if (!flowGraph.ContainsKey(address))
        //                    flowGraph.Add(address, flow);

        //                address += (uint)instruction.Length;
        //            }
        //            else if (UnconditionalJumpCodes.Contains(instruction.Mnemonic))
        //            {
        //                string destination = instruction.ToString().Split(' ')[1];
        //                uint i = uint.Parse(destination.Substring(2), NumberStyles.HexNumber);

        //                flow.Type = FlowType.Unconditional;
        //                flow.UnconditionalLink = i;

        //                if (!set.Contains(i))
        //                {
        //                    queue.Enqueue(i);
        //                    set.Add(i);
        //                }

        //                queue.Enqueue(i);

        //                if (!flowGraph.ContainsKey(address))
        //                    flowGraph.Add(address, flow);

        //                address = i;
        //            }
        //            else
        //            {
        //                address += (uint)instruction.Length;
        //            }

        //            instruction = _instructions[address];
        //        }
        //    }

        //    return flowGraph;
        //}

        //private class ControlFlow
        //{
        //    public FlowType Type { get; set; }
        //    public uint TrueLink { get; set; }
        //    public uint FalseLink { get; set; }
        //    public uint UnconditionalLink { get; set; }
        //}

        //private enum FlowType
        //{
        //    None, Unconditional, Conditional
        //}

        //private BasicBlock GenerateFunction(uint startAddress, Queue<uint> functionQueue)
        //{
        //    List<BasicBlock> blockLookup = new List<BasicBlock>();

        //    Queue<BasicBlock> blocks = new Queue<BasicBlock>();

        //    BasicBlock functionBlock = new BasicBlock { Address = startAddress };
        //    blocks.Enqueue(functionBlock);

        //    while (blocks.Count > 0)
        //    {
        //        BasicBlock block = blocks.Dequeue();
        //        blockLookup.Add(block);

        //        uint address = block.Address;
        //        while (true)
        //        {
        //            Instruction current = _instructions[address];
        //            block.Instructions.Add(current);

        //            string destination = current.ToString().Split(' ')[1];
        //            if (current.Mnemonic == ud_mnemonic_code.UD_Icall)
        //            {
        //                uint i = uint.Parse(destination.Substring(2), NumberStyles.HexNumber);

        //                functionQueue.Enqueue(i);
        //                address = (uint)(address + current.Length);
        //            }
        //            else if (ConditionalJumpCodes.Contains(current.Mnemonic))
        //            {
        //                uint i = uint.Parse(destination.Substring(2), NumberStyles.HexNumber);

        //                BasicBlock trueBranch = new BasicBlock { Address = i };
        //                blocks.Enqueue(trueBranch);
        //                blockLookup.Add(trueBranch);
        //                block.TrueBanch = trueBranch;
        //                BasicBlock falseBranch = new BasicBlock { Address = (uint)(address + current.Length) };



        //                //Enqueue both of them
        //                blocks.Enqueue(falseBranch);

        //                block.FalseBranch = falseBranch;

        //                break;
        //            }
        //            else if (UnconditionalJumpCodes.Contains(current.Mnemonic))
        //            {
        //                address = uint.Parse(destination.Substring(2), NumberStyles.HexNumber);

        //                //BasicBlock foundUBranch = Find(blockLookup, address);
        //                //if (foundUBranch != null)
        //                //{
        //                //    block.UnconditionalBranch = foundUBranch;
        //                //}
        //                //else
        //                //{
        //                //    BasicBlock branch = new BasicBlock { Address = address };
        //                //    blocks.Enqueue(branch);
        //                //    blockLookup.Add(branch);
        //                //    block.UnconditionalBranch = branch;
        //                //}


        //                BasicBlock branch;
        //                if (GetBlock(blockLookup, address, out branch))
        //                {
        //                    block.UnconditionalBranch = branch;
        //                }


        //                break;
        //            }
        //            else if (current.Mnemonic == ud_mnemonic_code.UD_Iret)
        //            {
        //                break;
        //            }
        //            else
        //            {
        //                address = (uint)(address + current.Length);
        //            }

        //            BasicBlock foundTrue = Find(blockLookup, address);
        //            if (foundTrue != null)
        //            {
        //                if (address == foundTrue.Address)
        //                {
        //                    block.UnconditionalBranch = foundTrue;
        //                }
        //                else
        //                {

        //                }

        //                break;
        //            }
        //        }

        //        //Calculate size of the block
        //        block.Size = block.Instructions.Select(i => i.Length).Aggregate((a, b) => a + b);
        //    }
        //    return functionBlock;
        //}

        //private bool GetBlock(List<BasicBlock> blocks, uint address, out BasicBlock outBlock)
        //{
        //    BasicBlock found = Find(blocks, address);
        //    if (found == null)
        //    {
        //        //Create new block, add to list
        //        BasicBlock block = new BasicBlock { Address = address };
        //        blocks.Add(block);
        //        outBlock = block;
        //        return true;
        //    }
        //    else
        //    {
        //        if (found.Address == address)
        //        {
        //            outBlock = found;
        //            return false;
        //        }
        //        else
        //        {
        //            BasicBlock split = Split(found, address);
        //            blocks.Add(split);
        //            outBlock = split;
        //            return false;
        //        }
        //    }
        //}

        //private BasicBlock Split(BasicBlock block, uint address)
        //{
        //    uint delta = address - block.Address;

        //    if (delta == 0)
        //        throw new Exception();

        //    int i = 0;
        //    int count = 0;
        //    while (delta != count)
        //    {
        //        count += block.Instructions[i].Length;
        //        i++;
        //    }

        //    block.Instructions = block.Instructions.Take(i).ToList();

        //    BasicBlock split = new BasicBlock
        //    {
        //        Address = address,
        //        Instructions = block.Instructions.Skip(i).ToList()
        //    };

        //    return split;
        //}

        //private BasicBlock Find(List<BasicBlock> blocks, uint address)
        //{
        //    foreach (BasicBlock block in blocks)
        //    {
        //        if ((address < block.Address + block.Size) && (address >= block.Address))
        //            return block;
        //    }

        //    return null;
        //}
    }
}
