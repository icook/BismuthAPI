import pprint
import time
import click
import sys
import logging
import rpcconnections

@click.group()
@click.option('--port', '-p', default=5658, help='bismuth api port')
@click.option('--host', '-h', default="127.0.0.1", help='bismuth api host')
@click.option('--verbose', '-v', default=False)
@click.option('--raw', '-r', default=False)
@click.pass_context
def cli(ctx, port, host, verbose, raw):
    connection = rpcconnections.Connection((host, port), verbose=verbose, raw=raw)
    ctx.obj['connection'] = connection

@cli.command()
@click.pass_context
def status(ctx):
    con = ctx.obj['connection']
    status = con.command('statusjson')
    pprint.pprint(status)
    balances = con.command('api_listbalance', [ [status['address'], ], 0, True])
    pprint.pprint(balances)

@cli.command()
@click.pass_context
@click.argument('count', type=int)
def mine(ctx, count):
    con = ctx.obj['connection']
    if con.mode() != "regnet":
        raise Exception("You can only generate blocks on fly in regtest")
    orig_height = con.height()
    print("Chain at height {}".format(orig_height))
    ret = con.command('regtest_generate', [count])
    assert ret == 'OK'
    for i in range(300):
        if (con.height() - orig_height) >= count:
            break
        time.sleep(0.1)
    else:
        print("Sorry, failed to mine")
        return
    print("Now at height {:,}".format(con.height()))

if __name__ == '__main__':
    logger = logging.getLogger('push')

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s [%(name)-15s] [%(levelname)-5s] %(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)

    cli(obj={})

