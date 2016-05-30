# A basic test of the link-layer address logging script

# @TEST-EXEC: bro -r $TRACES/q-in-q.trace %INPUT
# @TEST-EXEC: btest-diff conn.log

@load protocols/conn/mac-logging
