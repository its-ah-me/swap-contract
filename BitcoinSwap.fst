module BitcoinSwap

open Zen.Types
open Zen.Base
open Zen.Cost
open Zen.Asset
open Zen.Data
open Zen.Dictionary
open Zen.Array
open Zen.Crypto

module RT = Zen.ResultT
module OT = Zen.OptionT
module Tx = Zen.TxSkeleton
module C = Zen.Cost
module BTC = Zen.Bitcoin

assume val pklock: lock

let main txSkeleton context contractId command sender data wallet _ =
  let! txHash = parseHash "f804f2a0e743d9131f68603c65bb8412a3a7c815ed5ad36461fb2142ec87f066" in
  match command with
  | "checkPath" ->
    let! txIndex = data >!= tryDict >?= tryFind "txIndex" >?= tryU32 in
    let! header = data >!= tryDict >?= tryFind "header" >?= tryByteArray in

        let! auditPath = data >!= tryDict >?= tryFind "auditPath" >?= tryArray in
        begin
          match auditPath with
          | Some auditPath ->
            let auditPath = tryMap tryHash auditPath in
            begin
              match auditPath, txIndex, header, txHash with
              | Some auditPath, Some txIndex, Some header, Some txHash ->
                if length header <> 80 then
                  RT.autoFailw "bad header"
                else
                  let (|l, auditPath|): (t:nat& indexed hash t) = (|length auditPath, auditPath|) in
                  if l < 32 then
                    begin
                    let isValid: bool `cost` 17650 = BTC.checkInclusion auditPath txIndex txHash header |> inc (17650 - ((l +1) * 550 + 50)) in
                    if! isValid then
                      begin
                        let! txSkeleton = Tx.lockToAddress zenAsset 10UL pklock txSkeleton in
                        let! txSkeleton = Tx.fromWallet zenAsset 10UL contractId wallet txSkeleton in


                        let result =
                            match txSkeleton with
                            | Some tx -> Some @ { tx = tx; message = None; state = NoChange }
                            | None -> None in
                        RT.of_option "error" result
                      end
                    else
                      RT.autoFailw "Merkle proof is invalid"
                    end
                  else
                    RT.autoFailw "audit path out of bounds"
                | _ ->
                    RT.autoFailw "missing parameters"
              end
            | _ ->
                RT.autoFailw "bad audit path"
          end
  | _ ->
      RT.autoFailw "wrong command"

  let cf _ _ _ _ _ wallet _ =
  (32 +
        (4 + 64 + 2 +
        (4 + 64 + 2 + (4 + 64 + 4 + (17650 + (64 + (Zen.Wallet.size wallet * 128 + 192 + 0)))))) +
        105)
      |> cast nat
      |> C.ret
