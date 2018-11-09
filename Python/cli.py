import pprint
import time
import click
import sys
import logging
import rpcconnections
from tabulate import tabulate


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
    node_status = con.command('statusjson')
    pprint.pprint(node_status)
    balances = con.command('api_listbalance', [ [node_status['address'], ], 0, True])
    pprint.pprint(balances)


@cli.command()
@click.pass_context
@click.argument('path', type=str)
def new_wallet(ctx, path):
    wallet = rpcconnections.Wallet.generate()
    wallet.save(path)
    print("New wallet generated: {}".format(wallet.address))


@cli.command()
@click.pass_context
@click.argument('addresses', nargs=-1)
def balance(ctx, addresses):
    con = ctx.obj['connection']
    pprint.pprint(con.command('api_listbalance', [ addresses, 0, True]))


@cli.command()
@click.pass_context
@click.argument('address', type=str)
@click.option('--lookback', '-l', default=500)
def txs(ctx, address, lookback):
    con = ctx.obj['connection']
    since_block = max(0, con.height() - lookback)
    res = con.command(
        'api_getblocksincewhere', [since_block, "address = '{0}' or recipient = '{0}'".format(address)])
    res = [
        {'bh': r[0],
         'timestamp': r[1],
         'address': r[2],
         'recipient': r[3],
         'amount': r[4],
         'signature': r[5],
         'public_key': r[6],
         'block_hash': r[7],
         'fee': r[8],
         'reward': r[9],
         'operation': r[10],
         'openfield': r[11]} for r in res]
    for r in res:
        r.pop('timestamp')
        r.pop('public_key')
        r.pop('block_hash')
        r.pop('signature')
    print(tabulate(res, headers='keys'))

@cli.command()
@click.pass_context
@click.argument('wallet_path', type=str)
@click.argument('amount', type=float)
@click.argument('address', type=str)
@click.option('--openfield', '-o', default='')
def send(ctx, wallet_path, address, amount, openfield):
    con = ctx.obj['connection']
    wallet = rpcconnections.Wallet.load(wallet_path)
    con.send(wallet, address, amount, openfield=openfield)


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
    for _ in range(300):
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
