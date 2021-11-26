import React, { useEffect, useState } from 'react';
import { initialize } from 'zokrates-js';

import {
  doubleTransferNoHash,
  mimcHash2,
  mimcEncryption,
  mimcConstants,
  pad512ThenHash,
  pad4096ThenHash,
  pad1280ThenHash,
  hash1024,
  hash4608,
  hash1536,
  pathCheck,
  elgamal,
  elligator,
  chi,
  constPowerModofhalfp,
  montgomeryToTwistedEdwards,
} from './circuits';

export default function Zokrates() {
  const [proof, setProof] = useState('');
  useEffect(async () => {
    initialize().then(zokratesProvider => {
      // const source = "def main(private field a) -> (field): return a * a";
      const source = doubleTransferNoHash;
      const options = {
        location: 'main.zok', // location of the root module
        resolveCallback: (currentLocation, importLocation) => {
          console.log(`${currentLocation} is importing ' ${importLocation}`);
          let code;
          if (importLocation.endsWith('mimc-hash-2.zok')) code = mimcHash2;
          else if (importLocation.endsWith('mimc-encryption.zok')) code = mimcEncryption;
          else if (importLocation.endsWith('mimc-constants.zok')) code = mimcConstants;
          else if (importLocation.endsWith('pad512ThenHash.zok')) code = pad512ThenHash;
          else if (importLocation.endsWith('pad4096ThenHash.zok')) code = pad4096ThenHash;
          else if (importLocation.endsWith('pad1280ThenHash.zok')) code = pad1280ThenHash;
          else if (importLocation.endsWith('hash1024')) code = hash1024;
          else if (importLocation.endsWith('hash1536')) code = hash1536;
          else if (importLocation.endsWith('hash4608')) code = hash4608;
          else if (importLocation.endsWith('mimc-path-check.zok')) code = pathCheck;
          else if (importLocation.endsWith('el-gamal4')) code = elgamal;
          else if (importLocation.endsWith('elligator2.zok')) code = elligator;
          else if (importLocation.endsWith('chi.zok')) code = chi;
          else if (importLocation.endsWith('constPowerModOfhalfp-1.zok'))
            code = constPowerModofhalfp;
          else if (importLocation.endsWith('montgomeryToTwistedEdwards.zok'))
            code = montgomeryToTwistedEdwards;
          return {
            source: code,
            location: importLocation,
          };
        },
      };

      //starting double transfer inputs

      const publicInputsHash =
        '195705462433093164160198970181872324762589171366464260464698507023501599477';

      // oldcommitment

      const ercAddress1 = [
        '0',
        '0',
        '0',
        '3786913876',
        '4053413099',
        '4184556347',
        '2734706904',
        '2298878123',
      ];
      const id1 = ['0', '0', '0', '0', '0', '0', '0', '0'];
      const value1 = ['0', '0', '0', '0', '0', '0', '0', '10'];
      const salt1 = [
        '1469135657',
        '3547817087',
        '3627156699',
        '1826473963',
        '3395455363',
        '1963289040',
        '2300243491',
        '2635227071',
      ];
      const hash1 = [
        '718249098',
        '3022909697',
        '1671192172',
        '2208948825',
        '1647799669',
        '2348058262',
        '3463611109',
        '234453527',
      ];
      const ask1 = '6930558048592459968398874090872446840386493339700763487392344092914357738801';

      const ercAddress2 = [
        '0',
        '0',
        '0',
        '3786913876',
        '4053413099',
        '4184556347',
        '2734706904',
        '2298878123',
      ];
      const id2 = ['0', '0', '0', '0', '0', '0', '0', '0'];
      const value2 = ['0', '0', '0', '0', '0', '0', '0', '10'];
      const salt2 = [
        '712034866',
        '866054266',
        '3814000985',
        '4249096863',
        '4065113913',
        '2996438565',
        '3597388231',
        '1667885982',
      ];
      const hash2 = [
        '472587739',
        '1324918119',
        '1807033832',
        '1334073929',
        '3892559028',
        '3845398866',
        '3507663518',
        '2276201717',
      ];
      const ask2 = '6930558048592459968398874090872446840386493339700763487392344092914357738801';

      // const ercAddress = [ercAddress1,ercAddress2];
      // const id = [id1,id2];
      // const value = [value1,value2];
      // const salt = [salt1,salt2];
      // const hash = [hash1,hash2];
      // const ask = [ask1,ask2];

      const oldCommitment = [
        {
          ercAddress: ercAddress1,
          id: id1,
          value: value1,
          salt: salt1,
          hash: hash1,
          ask: ask1,
        },
        {
          ercAddress: ercAddress2,
          id: id2,
          value: value2,
          salt: salt2,
          hash: hash2,
          ask: ask2,
        },
      ];

      //newcommitment

      const pkdRecipient1 = [
        '11793120019061651548381689667193031350303535754993894421714575842003180702651',
        '19514094396296584559699296843667781122852060401076195850868925920595449006047',
      ];
      const valuenew1 = ['0', '0', '0', '0', '0', '0', '0', '12'];
      const saltnew1 = [
        '722291714',
        '228315248',
        '4230766893',
        '3118207945',
        '2114921271',
        '2563232911',
        '1656583439',
        '1253033227',
      ];
      const hashnew1 = [
        '766700354',
        '147937620',
        '2785490101',
        '4291751941',
        '1233082797',
        '3966472873',
        '3796597921',
        '3373794737',
      ];

      const pkdRecipient2 = [
        '11793120019061651548381689667193031350303535754993894421714575842003180702651',
        '19514094396296584559699296843667781122852060401076195850868925920595449006047',
      ];
      const valuenew2 = ['0', '0', '0', '0', '0', '0', '0', '8'];
      const saltnew2 = [
        '136433504',
        '1337838106',
        '633168311',
        '117499648',
        '2524841122',
        '3354944756',
        '2248600203',
        '4176565528',
      ];
      const hashnew2 = [
        '424493686',
        '2642163409',
        '697483979',
        '2479372125',
        '3894183691',
        '1075599147',
        '472292632',
        '1088332920',
      ];

      // const pkdRecipient=[pkdRecipient1,pkdRecipient2];
      // const valuenew=[valuenew1,valuenew2];
      // const saltnew=[saltnew1,saltnew2];
      // const hashnew=[hashnew1,hashnew2];

      const newcommitment = [
        {
          pkdRecipient: pkdRecipient1,
          value: valuenew1,
          salt: saltnew1,
          hash: hashnew1,
        },
        {
          pkdRecipient: pkdRecipient2,
          value: valuenew2,
          salt: saltnew2,
          hash: hashnew2,
        },
      ];

      // nullifier
      const nsk1 = [
        '356285367',
        '2834115112',
        '1573131528',
        '2110052527',
        '2559426218',
        '450338363',
        '1256702011',
        '376012475',
      ];
      const hashnullifier1 = [
        '3563012560',
        '1722307076',
        '1868988324',
        '4002677586',
        '444329017',
        '1649226761',
        '4244319893',
        '4178565931',
      ];

      const nsk2 = [
        '356285367',
        '2834115112',
        '1573131528',
        '2110052527',
        '2559426218',
        '450338363',
        '1256702011',
        '376012475',
      ];
      const hashnullifier2 = [
        '3797995479',
        '2976390213',
        '3926381743',
        '2553760934',
        '1851398911',
        '15864640',
        '3473969682',
        '3717448395',
      ];

      // const nsk=[nsk1,nsk2];
      // const hashnullifier=[hashnullifier1,hashnullifier2];

      const nullifier = [
        { nsk: nsk1, hash: hashnullifier1 },
        { nsk: nsk2, hash: hashnullifier2 },
      ];

      //path
      const path1 = [
        '9848372595527000825366890619909791447833514330793512651434986850763738890365',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '9089963908222878173858721868491910124194746957418056522719428017940747715206',
        '5118433466966831820438420098663644648526825394353070220663505701189092392946',
        '549910806880791907042548248274419814318862389602683254777483820202445993362',
      ];
      const path2 = [
        '9848372595527000825366890619909791447833514330793512651434986850763738890365',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '0',
        '11552442654508826149654886774876308010229326029958322167680405955306403648395',
        '12551167089847287146172369384959757494553892887769955115432676018965248419679',
        '16515498235611865686779230008265447109003540863944296109921874196599492180102',
      ];

      const path = [path1, path2];

      //order
      const order = ['1', '7'];

      //secrets

      const ephemeralKey1 = [
        '2129827346',
        '3441147575',
        '3884107326',
        '501296405',
        '2240612900',
        '583963365',
        '270926919',
        '2618972085',
      ];
      const ephemeralKey2 = [
        '608125466',
        '3522624716',
        '1745325056',
        '1607791244',
        '228083994',
        '3788127939',
        '2771410186',
        '1723109540',
      ];
      const ephemeralKey3 = [
        '543490650',
        '3463676825',
        '4194205226',
        '659739259',
        '937915931',
        '56711779',
        '555280795',
        '773095480',
      ];
      const ephemeralKey4 = [
        '1290754449',
        '1468679853',
        '2875774307',
        '3436896289',
        '2442542924',
        '3370482382',
        '262283555',
        '349683065',
      ];
      const cipherText = [
        '3326672909489186708519420638996056353117217772376348668329779576760108440014',
        '16806202016084875146896113403860246377443174042922673980488026005278330753941',
        '6951941870449626489444177940735942707870326843067336037618471192383475238212',
        '20331730984024839177990923633858473381203445048493233289418816711147372407428',
        '18661781758718819051696881645546430980236328026413752064646781663568641489134',
        '8982787204661894584551907996405529242689190541171355051399484698515407749983',
        '5262831906667333887462136384252612239053398492103220623741234810672192993471',
        '7910841102037593183198418128830295825356862409363641392039573546881027647660',
        '4951102841618728692358744332087328483194617518741162812969047661417418491269',
        '19961586398012037869885052811690931071209771057996663290771914300856040312275',
        '1586554545153379429389960649388861934493423109178926017373796924681468562384',
        '11740757888918081861097200205027115569893476742053038231718896569660210448299',
        '15648914622113562710613989089872482639197658102752542007084120831211228532108',
        '3138706800212162982181019785101003922245058289357923116887423470484828251245',
        '18752185544727639835435119980411269838308063077248642657061607036987314828662',
        '8415535102993153392347419300760726173523916865463802166922511306506066094160',
      ];
      const sqrtMessage1 =
        '9427050129567031675553048604712181295465196374683565284398992208923945768094';
      const sqrtMessage2 = '0';
      const sqrtMessage3 =
        '60102829190319644835548050675648710959043900249173724935020008846436767741';
      const sqrtMessage4 =
        '4911822733984811114102582488404510946695069101891373393475306749074065768275';

      const secrets = {
        ephemeralKey1: ephemeralKey1,
        ephemeralKey2: ephemeralKey2,
        ephemeralKey3: ephemeralKey3,
        ephemeralKey4: ephemeralKey4,
        cipherText: cipherText,
        sqrtMessage1: sqrtMessage1,
        sqrtMessage2: sqrtMessage2,
        sqrtMessage3: sqrtMessage3,
        sqrtMessage4: sqrtMessage4,
      };
      const artifacts = zokratesProvider.compile(source, options);
      // computation
      //const { witness, output } = zokratesProvider.computeWitness(artifacts, ['2']);
      const { witness, output } = zokratesProvider.computeWitness(artifacts, [
        oldCommitment,
        newcommitment,
        nullifier,
        path,
        order,
        secrets,
      ]);

      //   console.log(output, typeof output);
      //   // run setup
      console.log('setup start');
      const keypair = zokratesProvider.setup(artifacts.program);
      // generate proof
      const genProof = zokratesProvider.generateProof(artifacts.program, witness, keypair.pk);
      console.log(genProof);
      // export solidity verifier
      // const verifier = zokratesProvider.exportSolidityVerifier(keypair.vk, 'v1');
      // console.log(verifier);
      setProof(JSON.stringify(genProof, 2, 2));
      if (zokratesProvider.verify(keypair.vk, genProof)) {
        console.log('Proof is correct...');
      }
    });
  }, []);

  return (
    <div>
      <span>Double transfer work beigin</span>
      <p>{proof}</p>
    </div>
  );
}