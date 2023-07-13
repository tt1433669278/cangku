# coding=utf-8
"""
# Source location privacy in Cyber-physical systems

- 论文算法设计
    - 骨干网络构建
    - 虚假消息广播

"""
import heapq
import math
import random

from matplotlib.patches import Wedge

from cpsNetwork import *
from cpsAttacker import *
from cpsNode import *
import networkx as nx


class cpstopoFakeScheduling:
    """
	虚假源调度算法，包含两个阶段：
	1）骨干网络构建
	2）虚假消息调度
	--------------
	用例：
	# 生成对象
	fs = cpstopoFakeScheduling(G=cpsNetwork(nodeNumber=1000, areaLength=100, initEnergy=1e8, radius=10),\
							   Tmax=100, c_capture=1e-3)
	# 虚假源调度算法主函数
	fs.fakeScheduling()
	# 生成骨干网络
	fs.backbonePlot()
	# 结果绘制
	fs.plotDelayandConsumption()
	--------------
	变量成员：
	G          = 网络
	Tmax       = 最大周期数

	C_Capture  = 被捕获率阈值，1e-4
	C_alpha    = 超参数 alpha，0.5
	C_Beta     = 超参数 beta，0.5

	sink       = 基站编号
	sink_pos   = 基站位置，(0,0)
	source     = 源节点编号
	source_pos = 源节点位置，(0.45*20, 0.45*20)
	attacker   = 攻击者

	backbone   = 骨干网络
	safety     = 安全周期数
	listDelay  = 每周期的时延
	listEnergyConsumption = 每周期的传输能耗
	listFakeSource        = 每周期源节点序列，用节点编号表示
	--------------
	方法成员：
	__init__(G, Tmax, c_capture, c_alpha, c_beta, sink_pos, source_pos)
	display()
	generateSINKandSOURCE()
	deployAttacker(node)
	calculate2Distance(node1, node2)
	isConnected()
	searchDeepFirst(u, former, bestBackbone, target, likelihood, maxStep)
	generateBackbone()
	calculateFakeSource(node, Ti)
	delayModel(u, v)
	consumeEnergyModel(node)
	sendSource2Sink(Ti)
	scheduingFakeMessages()
	resultPlot()
	backbonePlot()
	fakeScheduling()     = 虚假源调度主算法入口
	"""

    def __init__(self, G=cpsNetwork(nodeNumber=10, areaLength=20, initEnergy=1e6, radius=10), Tmax=1000, c_capture=1e-4,
                 w_1=0.5, w_2=0.5, sink_pos=(0, 0), source_pos=(0.45 * 20, 0.4 * 20)):
        self.t_point = 1
        self.path = []
        self.dypath = []
        self.sum_path = []
        self.G = G
        self.Tmax = Tmax

        self.C_Capture = c_capture
        # self.C_Alpha = c_alpha
        # self.C_Beta = c_beta

        self.sink = -1
        self.sink_pos = sink_pos
        self.source = -1
        self.source_pos = source_pos
        self.attacker = cpsAttacker()

        self.safety = -1  # 网络安全周期
        self.listDelay = []  # 每个周期打网络时延
        self.listEnergyConsumption = []  # 每个周期的网络能耗
        self.listFakeSource = []  # 每个周期的虚假源部署情况
        self.open_set = []
        self.closed_set = []
        self.min_node = None
        self.nodenum = []
        self.w_1 = w_1
        self.w_2 = w_2
        print "参数 w_1：", self.w_1
        print "参数 w_2：", self.w_2

    def display(self):
        print "节点总数：", self.G.nodeNumber
        print "正方形区域边长：", self.G.areaLength
        print "节点初始能量：", self.G.initEnergy
        print "最大周期数：", self.Tmax
        print "节点通信半径：", self.G.radius
        print "捕获率阈值：", self.C_Capture
        # print "参数 alpha：", self.C_Alpha
        # print "参数 beta：", self.C_Beta
        print "sink 编号：", self.sink
        print "source 编号：", self.source

    def generateSINKandSOURCE(self):
        "部署 sink 和 source"
        self.sink = self.G.nodeNumber
        self.source = self.G.nodeNumber + 1
        sinkNode = cpsNode(identity=self.sink, position=self.sink_pos, energy=self.G.initEnergy * 100,
                           radius=self.G.radius, state='SINK', adj=set())
        sourceNode = cpsNode(identity=self.source, position=self.source_pos, energy=self.G.initEnergy * 100,
                             radius=self.G.radius, state='SOURCE', adj=set())
        num = self.G.nodeNumber
        self.G.addNode(sinkNode)
        self.G.addNode(sourceNode)
        if self.G.nodeNumber != num + 2:
            print "Error in the deployed sink and source."
            while len(self.G.nodeList) > num:
                self.G.nodeList.pop()
        else:
            for i in self.G.nodeList[self.sink].adj:  # 把sik点和source点加到邻居列表中
                self.G.nodeList[i].adj.add(self.sink)
            for i in self.G.nodeList[self.source].adj:
                self.G.nodeList[i].adj.add(self.source)

    def deployAttacker(self, Node):
        """
		部署攻击者初始位置，位于 sink
		"""
        self.attacker.initDeploy(Node)

    def generateNetworkLevel(self):
        print "构建网络层次"
        queue = Queue.Queue()
        visited = np.zeros(self.G.nodeNumber, dtype=np.int8)

        self.G.nodeList[self.sink].level = 0
        queue.put(self.sink)
        visited[self.sink] = 1
        # 计算节点与基站之间最短的跳数
        while not queue.empty():
            u = queue.get()
            visited[u] = 0
            for v in self.G.nodeList[u].adj:
                if self.G.nodeList[v].level == -1 or self.G.nodeList[u].level + 1 < self.G.nodeList[v].level:
                    self.G.nodeList[v].level = self.G.nodeList[u].level + 1
                    if visited[v] == 0:
                        queue.put(v)
                        visited[v] = 1

    def getResult4AnalysisEachRound(self, Ti):
        """
        获取用于评估算法性能的方法
        :return: 性能指标
        """
        if Ti == 1:
            self.result = []
        each_result = []
        # hop from sink to source
        each_result.append(len(self.sum_path) - 1)
        # number of transmitted and broadcast fake messages对邻接矩阵的每一行进行求最大值的操作，得到一个包含每个节点传输和接收的边数的数组
        each_result.append(np.max(self.G.adjacentMatrix, axis=1).sum() - len(self.sum_path) + 1)
        self.result.append(each_result)

    def calculate_distance(self, node1, node2):
        a = ((node1.position[0] - node2.position[0]) ** 2 + (
                node1.position[1] - node2.position[1]) ** 2) ** 0.5  # 计算两个节点之间的距离（例如欧氏距离）
        return a

    def heuristic(self, node, target):
        dx = abs(node.position[0] - target.position[0])  # 节点的x坐标与目标节点的x坐标之差
        dy = abs(node.position[1] - target.position[1])  # 节点的y坐标与目标节点的y坐标之差
        return dx + dy  # 曼哈顿距离为两个坐标差值的绝对值之和
        #
        # print dx, dy, node.identity
        # return math.sqrt(dx * dx + dy * dy)

        # b = self.calculate_distance(node, target)  # 启发式函数，估计从当前节点到目标节点的距离（例如欧氏距离）
        # return b

    def reconstruct_path(self, node):  # 从目标节点回溯到起始节点，构建最短路径
        path = []
        current = node
        while current is not None:
            path.append(self.G.nodeList[current].identity)
            current = self.G.nodeList[current].parent
        path.reverse()
        # print path
        return path

    def find_shortest_path(self, start, target):
        self.G.nodeList[start].g_cost = 0  # g_cost 是从起始节点到当前节点的实际代价（距离）。对于起始节点来说，它的代价为0
        self.G.nodeList[start].h_cost = self.heuristic(self.G.nodeList[start], self.G.nodeList[
            target])  # h_cost 是启发式函数计算得到的估计代价（距离），用于估计当前节点到目标节点的距离。
        self.G.nodeList[start].f_cost = self.G.nodeList[start].g_cost + self.G.nodeList[
            start].h_cost  # f_cost 是总代价，即从起始节点经过当前节点到目标节点的总代价。
        heapq.heappush(self.open_set, start)  # 将节点 start 添加到开列表
        g_temp = 0
        ti = 1
        mina = float('inf')
        min_node = None
        print "正在构建骨干.............."
        while self.open_set:
            if ti == 1:
                current = heapq.heappop(self.open_set)
                ti = 2
            else:
                mina = float('inf')
                min_node = None
                for node in self.open_set:
                    if self.G.nodeList[node].f_cost < mina:
                        mina = self.G.nodeList[node].f_cost
                        min_node = node
                        current = min_node
                        ti = 3
                self.open_set = []
            if current == self.G.nodeList[target].identity:
                # 找到最短路径
                print "OK 找到最短路径"
                path = self.reconstruct_path(current)
                print "path:", path
                return path
            # current_ = self.G.nodeList[start]
            c = 0
            if ti == 3:
                b = self.calculate_distance(self.G.nodeList[current], self.G.nodeList[current_])
                c += b
            self.closed_set.append(current)
            # mina = 10000
            # self.min_node = None
            for neighbor in self.G.nodeList[current].adj:
                if neighbor in self.closed_set:
                    continue

                if neighbor not in self.open_set:
                    self.G.nodeList[neighbor].parent = current
                    d = self.calculate_distance(self.G.nodeList[current], self.G.nodeList[start])
                    g_temp = self.calculate_distance(self.G.nodeList[current], self.G.nodeList[neighbor]) + c
                    self.G.nodeList[neighbor].g_cost = g_temp
                    self.G.nodeList[neighbor].h_cost = self.heuristic(self.G.nodeList[neighbor],
                                                                      self.G.nodeList[target])
                    self.G.nodeList[neighbor].f_cost = self.G.nodeList[neighbor].g_cost + self.G.nodeList[
                        neighbor].h_cost
                    f_temp = self.G.nodeList[neighbor].g_cost + self.G.nodeList[neighbor].h_cost
                    heapq.heappush(self.open_set, neighbor)
            current_ = current
            # 二版
            #     g_temp = self.calculate_distance(self.G.nodeList[current], self.G.nodeList[neighbor])
            #     self.G.nodeList[neighbor].g_cost = g_temp
            #     self.G.nodeList[neighbor].h_cost = self.heuristic(self.G.nodeList[neighbor], self.G.nodeList[target])
            #     f_temp = self.G.nodeList[neighbor].g_cost + self.G.nodeList[neighbor].h_cost
            #     self.G.nodeList[neighbor].f_cost = self.G.nodeList[neighbor].g_cost + self.G.nodeList[neighbor].h_cost
            #     if self.G.nodeList[neighbor].f_cost < mina:
            #         mina = self.G.nodeList[neighbor].f_cost
            #         # self.G.nodeList[neighbor].parent = current
            #         min_node = self.G.nodeList[neighbor].identity
            #
            # if min_node not in self.open_set:
            #     self.G.nodeList[min_node].parent = current
            #     heapq.heappush(self.open_set, min_node)
            # 一版
            # if neighbor not in self.open_set:
            #     # if self.G.nodeList[neighbor].level < self.G.nodeList[current].level:
            #     self.G.nodeList[neighbor].parent = current
            #     # g_temp += self.calculate_distance(self.G.nodeList[current], self.G.nodeList[neighbor])
            #     self.G.nodeList[neighbor].g_cost = g_temp
            #     self.G.nodeList[neighbor].h_cost = self.heuristic(self.G.nodeList[neighbor], self.G.nodeList[target])
            #     self.G.nodeList[neighbor].f_cost = self.G.nodeList[neighbor].g_cost + self.G.nodeList[
            #         neighbor].h_cost
            #     heapq.heappush(self.open_set, neighbor)

            # if self.G.nodeList[neighbor].f_cost < mina:
            #     mina = self.G.nodeList[neighbor].f_cost
            #     self.min_node = self.G.nodeList[neighbor].identity
            #     min_node = self.G.nodeList[neighbor]
            # # print"最小的 f_cost 值：", mina
            # # print"对应的节点：", min_node.identity
            #     min_node.parent = current
            #
            # heapq.heappush(self.open_set, self.min_node)

        # 未找到路径
        return None

    def theend(self):
        st = self.G.nodeList[self.source].identity
        et = self.G.nodeList[self.sink].identity
        gd_path = self.find_shortest_path(st, et)
        self.sum_path = gd_path
        print "self.sum_path = ", self.sum_path
        return self.path

    def calculateFakeSource(self, node, Ti):
        """
        计算节点间通信的概率，并返回 True/False 值
        PS: sink, source, backbone 不会成为 fake source
        """
        if node.state == "SINK" or node.state == "SOURCE":
            return False
        B = set(self.sum_path)
        if node.identity in B:
            return False

        # I_v_i^B
        numB = 0
        for v in node.adj:  # 如果邻居点有骨干节点的+1
            if v in B:
                numB += 1
        # rank_v_i^E
        rankEV = -1  # 节点能耗排名，周围节点少说明在稀疏地段需要通过更长的跳数来传输数据会消耗更多的能量
        if Ti == 1:
            rankEV = 1. / len(node.adj)
        else:
            rank = 1
            for v in node.adj:
                V = self.G.nodeList[v]
                if V.energy > node.energy:  # 计算节点能耗排名，能耗多的排名靠前
                    rank += 1
            rankEV = rank * 1. / len(node.adj)
        # I_v_i^C  循环统计了节点node的邻居节点中具有连接强度为1的节点的数量
        numC = 0
        dist = 0
        if Ti == 1:
            numC = 0
        else:
            for v in node.adj:
                V = self.G.nodeList[v]
                if V.weight == 1:
                    numC += 1
        # C(p_i^T(l-1))
        CP = 0
        if Ti == 1:
            CP = 0
        else:
            CP = node.weight
        # p_i
        for i in node.adj:
            dist += self.G.calculate2Distance(self.G.nodeList[i], node)
        CD = self.w_1 * len(node.adj) + self.w_2 * dist + (1. - rankEV * 1. / len(node.adj)) + np.exp(
            CP - numC * 1. / len(node.adj))
        cd1 = np.exp(numB * 1. / len(node.adj)) / CD

        # numI = len(node.adj)
        # p_i_z = self.C_Alpha * np.exp(numB * 1. / numI)  # 分子
        # p_i_m = self.C_Beta * np.exp(1. - rankEV * 1. / numI) + (1 - self.C_Beta) * np.exp(CP - numC * 1. / numI)  # 分母
        # p_i = p_i_z / p_i_m  # 概率阈值
        # 是否广播
        RAND = np.random.rand()
        if RAND < cd1:
            return True
        else:
            return False

    def sendSource2Sink(self, Ti):
        """
        一个周期内容事件：
        1）主要事件：源节点发送消息，并通过骨干网络传输至基站
        2）攻击者移动模型
        3）虚假源广播
        更新的参数：
        1）节点剩余能量
        2）攻击者位置
        返回值：
        1）源节点是否被捕获
        2）源节点消息上传到基站的时间花费
        3）网络能耗
        """
        flag = False
        packetSize = 500 * 8  # 单次数据包大小 bit
        # 路由时延
        delayTi = 0
        energyTi = 0
        for (u, v) in zip(self.sum_path[:-1], self.sum_path[1:]):
            self.G.adjacentMatrix[u, v] = 1
            delayTi += self.G.delayModelusingAdjMatrix(u, v) * packetSize
        # 网络能耗
        for node in self.G.nodeList:
            ec = self.G.energyModelusingAdjMatrix(node) * packetSize
            energyTi += ec
            self.G.nodeList[node.identity].energy -= ec
            if node.energy <= 1e7:
                print node.identity, "is zro"
            if not self.G.nodeList[node.identity].isAlive():
                print "energy is no"
                flag = True
        # 攻击者移动
        self.attacker.move(self.G)
        # 源节点是否被捕获
        if self.attacker.position.identity == self.source:
            print "BE CAPTURE"
            flag = True
        # 每个周期执行的监听函数，用于获取网络信息
        self.getResult4AnalysisEachRound(Ti)
        return flag, delayTi, energyTi

    def updateAdjMatrix(self):
        """
        更新通信矩阵
        fake source broadcast a message to neighbors:通过更新通信矩阵，将虚假消息源节点与其邻居节点之间的通信关系标记为1
            self.G.adjacentMatrix['FAKE', neighbors] = 1  模拟虚假消息的传播过程。
        """
        self.G.initAdjMatrix()
        for node in self.G.nodeList:
            if node.state == 'FAKE':
                for v in node.adj:
                    self.G.adjacentMatrix[node.identity, v] = 1

    def scheduingFakeMessages(self):
        """
        虚假消息调度
        """
        listDelay = []
        listEnergyConsumption = []
        safety = -1
        for Ti in range(1, self.Tmax + 1):
            if Ti % 100 == 0:
                print Ti
            elif Ti % 10 == 0:
                print Ti,
            # fake source scheduling
            # self.theend()
            for node in self.G.nodeList:
                if node.identity != self.sink and node.identity != self.source:
                    self.G.nodeList[node.identity].state = 'FAKE' if self.calculateFakeSource(node, Ti) else 'NORMAL'
                # if node.identity
            # update 节点权重，1：fake，0：not fake
            self.updateAdjMatrix()
            self.listFakeSource.append([node.identity for node in self.G.nodeList if node.state == 'FAKE'])
            a = len(self.listFakeSource[Ti - 1])
            b = len(self.path)
            c = len(self.dypath)
            d = a + b + c
            e = ((d - 1) * 100 / float(self.G.nodeNumber))
            self.nodenum.append(e)

            # 源节点发送消息给基站的事件
            flag, delayTi, energyTi = self.sendSource2Sink(Ti)
            # 保存每轮的记录
            listDelay.append(delayTi)
            listEnergyConsumption.append(energyTi)
            if flag or Ti == self.Tmax:
                safety = Ti
                print "\n GAME OVER !!!!!!!!!!!!!!!!"
                break
        return safety, listDelay, listEnergyConsumption

    def plotDelayandConsumption(self):
        """
        曲线：
        1）每轮的网络时延
        2）每轮的能耗
        """
        plt.figure(figsize=(15, 6))
        plt.plot(np.array(self.listEnergyConsumption))
        plt.title("Consumption")
        plt.show()

        plt.figure(figsize=(15, 6))
        plt.plot(np.array(self.listDelay) / 1e9)
        plt.title("Delay")
        plt.show()

    def useofnode(self):
        plt.figure(figsize=(15, 6))
        plt.plot(self.nodenum)
        plt.title("node use %")
        plt.show()

    def backbonePlot(self):
        """
        骨干网络绘制
        """
        ax = plt.figure(figsize=(20, 20))
        temp_x = []
        temp_y = []
        # 源节点坐标
        source_x = self.G.nodeList[self.source].position[0]
        source_y = self.G.nodeList[self.source].position[1]
        # 汇聚节点
        sink_x = self.G.nodeList[self.sink].position[0]
        sink_y = self.G.nodeList[self.sink].position[1]

        # 骨干网络
        """
        start->dong dong->end
        bakbone: start->end
        """

        for i, v in enumerate(self.sum_path):
            if i == 0:
                u = v
                continue
            else:
                U = self.G.nodeList[u]
                V = self.G.nodeList[v]
                x = [U.position[0], V.position[0]]
                y = [U.position[1], V.position[1]]
                plt.plot(x, y, 'k')  # 绘制两点之间连线
                u = v
        # 骨干节点
        temp_x = []
        temp_y = []
        fake_x = []
        fake_y = []
        for i in self.G.nodeList:
            if i.state == 'FAKE':
                fake_x.append(i.position[0])
                fake_y.append(i.position[1])
        # plt.plot(temp_x, temp_y, 'ro')  # ro红圆ko黑圆wo白圆rs红方
        plt.axis("equal")
        plt.plot(source_x, source_y, 'rs')
        plt.plot(sink_x, sink_y, 'rs')
        plt.plot(fake_x, fake_y, 'rs')
        # plt.plot(self.listFakeSource[0], self.listFakeSource[1], 'bs')
        plt.show()

    def fakeScheduling(self):
        sum_delay = 0
        self.generateSINKandSOURCE()
        self.deployAttacker(self.G.nodeList[self.sink])  # 部署攻击者位置
        # self.select_random_point(self.source_pos, self.sink_pos, 6, 45)  # 点
        self.theend()
        self.safety, self.listDelay, self.listEnergyConsumption = self.scheduingFakeMessages()  # 虚假源调度与网络路由事件
        for i in range(len(self.listDelay)):
            sum_delay += self.listDelay[i]
            mean_delay = sum_delay / (i + 1)
        print "\nThe safety is", self.safety, "\nThe every listDelay is", self.listDelay, "\nThe SumDelay is", sum_delay, "\nThe MeanDelay is", mean_delay


# def test(self):
#     print self.attacker.position.identity


if __name__ == '__main__':
    # network = cpsNetwork(file_path='load_network/temp_network.csv')
    network = cpsNetwork(file_path='load_network/network.csv')
    print '网络规模：', network.nodeNumber, network.areaLength

    fs = cpstopoFakeScheduling(G=network,
                               Tmax=2000, c_capture=1e-40, w_1=0.051, w_2=0.4,
                               sink_pos=(-200, -200), source_pos=(200, 200))
    fs.fakeScheduling()

    # print np.array(fs.result)

    restEnergy = [fs.G.initEnergy - node.energy for node in fs.G.nodeList if
                  node.identity != fs.source and node.identity != fs.sink]
    # print restEnergy
    print "\nThe maxrestEnergy is", max(restEnergy), "\nThe neanrestEnergy is", np.mean(
        restEnergy), "\nThe minrestEnergy is", min(restEnergy), "\nThe stdrestEnergy is", np.std(restEnergy)
    # 最大值、平均值、最小值和标准差
    fs.backbonePlot()
    fs.plotDelayandConsumption()
    fs.useofnode()
    # 每轮的虚假源节点数量
    a = [len(x) for x in fs.listFakeSource]
    print 'a', a
    plt.figure(figsize=(15, 3))
    plt.plot(a)
    plt.ylabel('The number of fake source')
    plt.show()
    fs.attacker.display()
