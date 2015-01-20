from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        leftHost1 = self.addHost( 'h1' )
        rightHost1 = self.addHost( 'h3' )
        leftHost2 = self.addHost( 'h2' )
        rightHost2 = self.addHost( 'h4' )
        leftSwitch = self.addSwitch( 's3' )
        rightSwitch = self.addSwitch( 's4' )
        topSwitch = self.addSwitch('s5')

        # Add links
        self.addLink( leftSwitch, leftHost1, 1 )
        self.addLink( leftSwitch, rightHost1, 2 )
        self.addLink( rightSwitch, leftHost2, 1 )
        self.addLink( rightSwitch, rightHost2, 2 )
        self.addLink( leftSwitch, rightSwitch, 3, 3)
        self.addLink( leftSwitch, topSwitch, 4, 1)
        self.addLink( rightSwitch, topSwitch, 4, 2)


topos = { 'mytopo': ( lambda: MyTopo() ) }


