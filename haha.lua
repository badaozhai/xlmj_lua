--
-- Created by IntelliJ IDEA.
-- User: Administrator
-- Date: 2016/10/18
-- Time: 17:11
--
--这个dissector只是把几个协议组合起来而已，并不是识别一种新的协议
do --do...end是Lua语言的语句块关键字，相当于C#语言的{..}
--创建一个Proto类的对象，表示一种协议
local p_multi = Proto("multi","MultiProto");
local vs_protos = {
    [2] = "mtp2",
    [3] = "mtp3",
    [4] = "alcap",
    [5] = "h248",
    [6] = "ranap",
    [7] = "rnsap",
    [8] = "nbap"
}
--创建几个ProtoField对象，就是主界面中部Packet Details窗格中能显示的那些属性
local f_proto = ProtoField.uint8("multi.protocol","Protocol",base.DEC,vs_protos)
local f_dir = ProtoField.uint8("multi.direction","Direction",base.DEC,{ [1] = "incoming", [0] = "outgoing"})
local f_text = ProtoField.string("multi.text","Text")
--把ProtoField对象加到Proto对象上
p_multi.fields = { f_proto, f_dir, f_text }
--用Dissector.get函数可以获得另外一个协议的解析组件
local data_dis = Dissector.get("data")
local protos = {
    [2] = Dissector.get("mtp2"),
    [3] = Dissector.get("mtp3"),
    [4] = Dissector.get("alcap"),
    [5] = Dissector.get("h248"),
    [6] = Dissector.get("ranap"),
    [7] = Dissector.get("rnsap"),
    [8] = Dissector.get("nbap"),
    [9] = Dissector.get("rrc"),
    [10] = DissectorTable.get("sctp.ppi"):get_dissector(3), -- m3ua
    [11] = DissectorTable.get("ip.proto"):get_dissector(132), -- sctp
}
--为Proto对象添加一个名为dissector的函数，
--Wireshark会对每个“相关”数据包调用这个函数
function p_multi.dissector(buf,pkt,root)
    --root:add会在Packet Details窗格中增加一行协议
    local t = root:add(p_multi,buf(0,2))
    --t:add，在Packet Details窗格中增加一行属性，
    --并指定要鼠标点击该属性时Packet Bytes窗格中会选中哪些字节
    t:add(f_proto,buf(0,1))
    t:add(f_dir,buf(1,1))
    --这句是将数据的第一个字节转换成无符号整数
    local proto_id = buf(0,1):uint()
    local dissector = protos[proto_id]
    if dissector ~= nil then
        dissector:call(buf(2):tvb(),pkt,root)
    elseif proto_id < 2 then
        t:add(f_text,buf(2))
        -- pkt.cols.info:set(buf(2,buf:len() - 3):string())
    else
        --调用另外一个dissector
        data_dis:call(buf(2):tvb(),pkt,root)
    end
end
--所有的dissector都是以“table”的形式组织的，table表示上级协议
local wtap_encap_table = DissectorTable.get("wtap_encap")
--这个是获得udp协议的DissectorTable，并且以端口号排列
local udp_encap_table = DissectorTable.get("udp.port")
wtap_encap_table:add(wtap.USER15,p_multi)
wtap_encap_table:add(wtap.USER12,p_multi)
--为UDP的7555端口注册这个Proto对象，
--当遇到源或目的为UDP7555的数据包，就会调用上面的p_multi.dissector函数
udp_encap_table:add(7555,p_multi)
end