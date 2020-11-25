"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        server= self.addHost( 'server' )
        client1 = self.addHost( 'client1' )
        client2 = self.addHost( 'client2' )
        client3 = self.addHost( 'client3' )
        client4 = self.addHost( 'client4' )
        client5 = self.addHost( 'client5' )
        switch1 = self.addSwitch( 's1' )


        # Add links
        self.addLink( server, switch1)
        self.addLink( client1, switch1 )
        self.addLink( client2, switch1 )
        self.addLink( client3, switch1)
        self.addLink( client4, switch1 )
        self.addLink( client5, switch1 )
        



topos = { 'mytopo': ( lambda: MyTopo() ) }

